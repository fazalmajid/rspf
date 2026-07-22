use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use rspf::config::Config;
use rspf::server::{self, AppState};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

#[derive(Debug, Parser)]
#[command(name = "rspfd", about = "Postfix SPF policy delegation daemon")]
struct Args {
    /// Path to the rspf.toml config file.
    #[arg(long, default_value = "/etc/rspf/rspf.toml")]
    config: PathBuf,

    /// Load and validate the config file, then exit.
    #[arg(long)]
    check_config: bool,

    /// Print a fully commented example config to stdout, then exit.
    #[arg(long)]
    dump_example_config: bool,
}

fn load_config(path: &Path) -> anyhow::Result<Config> {
    Config::load(path).map_err(|e| anyhow::anyhow!("loading {}: {e}", path.display()))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.dump_example_config {
        print!("{}", rspf::config::EXAMPLE_TOML);
        return Ok(());
    }

    let config = load_config(&args.config)?;

    if args.check_config {
        println!(
            "config OK: {} listener(s) configured",
            config.server.listen.len()
        );
        return Ok(());
    }

    rspf::logging::init(config.log.level);
    rspf::mail_log::init();

    let shutdown = CancellationToken::new();
    let signal_shutdown = shutdown.clone();
    tokio::spawn(async move {
        // daemontools' `svc -d`/`svc -t` send SIGTERM to stop a service;
        // also honor SIGINT for interactive/foreground use.
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
        info!("received shutdown signal");
        signal_shutdown.cancel();
    });

    let state = Arc::new(AppState::new(config)?);
    spawn_reload_on_sighup(state.clone(), args.config.clone());

    server::run(state, shutdown).await?;
    Ok(())
}

/// On SIGHUP, reload config and whitelist from disk and swap them into the
/// running state. A reload that fails to load/validate leaves the current
/// config in place (logged as an error) rather than crashing the daemon.
fn spawn_reload_on_sighup(state: Arc<AppState>, config_path: PathBuf) {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to install SIGHUP handler; config hot-reload is unavailable");
            return;
        }
    };

    tokio::spawn(async move {
        loop {
            if sighup.recv().await.is_none() {
                return;
            }
            info!("received SIGHUP, reloading config");
            match load_config(&config_path) {
                Ok(new_config) => match rspf::whitelist::Whitelist::load(&new_config.whitelist) {
                    Ok(new_whitelist) => {
                        state.whitelist.store(Arc::new(new_whitelist));
                        state.config.store(Arc::new(new_config));
                        info!("config reloaded successfully");
                    }
                    Err(e) => {
                        error!(error = %e, "reload failed loading whitelist, keeping previous config")
                    }
                },
                Err(e) => {
                    error!(error = %e, "reload failed loading config, keeping previous config")
                }
            }
        }
    });
}
