use std::sync::Arc;

use arc_swap::ArcSwap;
use futures_util::{SinkExt, StreamExt};
use hickory_resolver::error::ResolveError;
use tokio::net::{TcpListener, UnixListener};
use tokio_util::codec::Framed;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::{Config, ListenAddr};
use crate::engine::{self, DecisionContext};
use crate::proto::{Action, PolicyRequestCodec};
use crate::spf::{HickoryLookup, OverrideLookup, SpfEvaluator};
use crate::whitelist::{Whitelist, WhitelistError};

type Evaluator = SpfEvaluator<OverrideLookup<HickoryLookup>>;

#[derive(Debug, thiserror::Error)]
pub enum AppStateError {
    #[error("DNS resolver setup failed: {0}")]
    Resolver(#[from] ResolveError),
    #[error("loading whitelist: {0}")]
    Whitelist(#[from] WhitelistError),
}

pub struct AppState {
    pub config: ArcSwap<Config>,
    pub whitelist: ArcSwap<Whitelist>,
    pub evaluator: Evaluator,
}

impl AppState {
    pub fn new(config: Config) -> Result<Self, AppStateError> {
        let lookup = HickoryLookup::from_system_conf()?;
        let overrides = Arc::new(config.overrides.clone());
        let lookup = OverrideLookup::new(lookup, overrides);
        let evaluator = SpfEvaluator::new(lookup, &config.spf);
        let whitelist = Whitelist::load(&config.whitelist)?;
        Ok(Self {
            whitelist: ArcSwap::from_pointee(whitelist),
            config: ArcSwap::from_pointee(config),
            evaluator,
        })
    }
}

/// Whether a request should bypass SPF evaluation entirely: connections from
/// `skip.addresses`/`relay.trusted_relays`, SASL-authenticated senders (when
/// configured to be exempt), or anything matching the static whitelist.
fn should_skip(
    state: &AppState,
    req: &crate::proto::PolicyRequest,
    client_ip: std::net::IpAddr,
    helo: &str,
    sender: &str,
) -> Option<&'static str> {
    let config = state.config.load();

    if config.skip.addresses.contains(client_ip) {
        return Some("client_address matches skip.addresses");
    }
    if config.relay.trusted_relays.contains(client_ip) {
        return Some("client_address matches relay.trusted_relays");
    }
    if config.relay.exempt_sasl_authenticated
        && req.sasl_username.as_deref().is_some_and(|u| !u.is_empty())
    {
        return Some("sasl_username present and relay.exempt_sasl_authenticated is set");
    }

    let mail_from_domain = sender.rsplit_once('@').map(|(_, domain)| domain);
    let whitelist = state.whitelist.load();
    match whitelist.matches(
        client_ip,
        helo,
        mail_from_domain,
        req.reverse_client_name.as_deref(),
    ) {
        Some(reason) => Some(match reason {
            crate::whitelist::WhitelistReason::Ip => "whitelist.ips",
            crate::whitelist::WhitelistReason::Helo => "whitelist.helo_names",
            crate::whitelist::WhitelistReason::Domain => "whitelist.domains",
            crate::whitelist::WhitelistReason::DomainPtr => "whitelist.domains_ptr",
        }),
        None => None,
    }
}

/// Decide the response for one request: short-circuit exempt connections,
/// otherwise run SPF evaluation for both identities and hand the outcomes to
/// the policy decision engine.
async fn handle_request(state: &AppState, req: &crate::proto::PolicyRequest) -> Action {
    let (Some(helo), Some(sender), Ok(client_ip)) = (
        req.helo_name.as_deref(),
        req.sender.as_deref(),
        req.client_ip(),
    ) else {
        debug!("policy request missing helo/sender/client_address, answering dunno");
        return Action::Dunno;
    };
    let recipient = req.recipient.as_deref().unwrap_or_default();

    if let Some(reason) = should_skip(state, req, client_ip, helo, sender) {
        debug!(client_address = %client_ip, helo, sender, reason, "skipping SPF check");
        return Action::Dunno;
    }

    let config = state.config.load();
    let unwrapped_sender;
    let sender = match crate::srs::try_unwrap(sender, &config.srs) {
        crate::srs::SrsUnwrap::Valid { original_sender } => {
            debug!(client_address = %client_ip, raw_sender = sender, original_sender, "unwrapped SRS sender");
            unwrapped_sender = original_sender;
            unwrapped_sender.as_str()
        }
        crate::srs::SrsUnwrap::NotSrs
        | crate::srs::SrsUnwrap::InvalidHash
        | crate::srs::SrsUnwrap::Expired => sender,
    };

    let (helo_outcome, mail_from_outcome) = tokio::join!(
        state.evaluator.check_helo(client_ip, helo),
        state.evaluator.check_mail_from(client_ip, sender, helo),
    );

    let ctx = DecisionContext {
        ip: client_ip,
        sender,
        helo,
        recipient,
    };
    let action = engine::decide(&config, &helo_outcome, &mail_from_outcome, &ctx);

    debug!(
        client_address = %client_ip,
        helo,
        sender,
        helo_result = %helo_outcome.result,
        mail_from_result = %mail_from_outcome.result,
        action = %action,
        "evaluated SPF"
    );
    crate::mail_log::log_evaluated_spf(
        req.queue_id.as_deref(),
        client_ip,
        req.reverse_client_name.as_deref(),
        helo,
        sender,
        &helo_outcome.result,
        &mail_from_outcome.result,
        &action,
    );

    action
}

async fn handle_connection<S>(stream: S, state: Arc<AppState>, shutdown: CancellationToken)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut framed = Framed::new(stream, PolicyRequestCodec);
    loop {
        let next = tokio::select! {
            _ = shutdown.cancelled() => break,
            next = framed.next() => next,
        };

        let Some(result) = next else {
            break; // client closed the connection
        };

        let req = match result {
            Ok(req) => req,
            Err(e) => {
                warn!(error = %e, "failed to decode policy request, closing connection");
                break;
            }
        };

        let action = handle_request(&state, &req).await;
        if let Err(e) = framed.send(action).await {
            warn!(error = %e, "failed to write policy response, closing connection");
            break;
        }
    }
}

async fn run_tcp_listener(
    addr: std::net::SocketAddr,
    state: Arc<AppState>,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "listening (tcp)");
    loop {
        let accepted = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        debug!(%peer, "accepted connection");
        let state = state.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            handle_connection(stream, state, shutdown).await;
        });
    }
}

async fn run_unix_listener(
    path: std::path::PathBuf,
    state: Arc<AppState>,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    // Remove a stale socket file from a previous run, if any.
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    info!(path = %path.display(), "listening (unix)");
    loop {
        let accepted = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            accepted = listener.accept() => accepted,
        };
        let (stream, _addr) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        debug!("accepted connection");
        let state = state.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            handle_connection(stream, state, shutdown).await;
        });
    }
}

/// Runs one accept loop per configured listener until `shutdown` is cancelled.
pub async fn run(state: Arc<AppState>, shutdown: CancellationToken) -> std::io::Result<()> {
    let listeners = state.config.load().server.listen.clone();

    let mut tasks = Vec::new();
    for listen in listeners {
        let state = state.clone();
        let shutdown = shutdown.clone();
        match listen {
            ListenAddr::Tcp(addr) => {
                tasks.push(tokio::spawn(async move {
                    run_tcp_listener(addr, state, shutdown).await
                }));
            }
            ListenAddr::Unix(path) => {
                tasks.push(tokio::spawn(async move {
                    run_unix_listener(path, state, shutdown).await
                }));
            }
        }
    }

    for task in tasks {
        task.await??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn test_config(addr: std::net::SocketAddr) -> Config {
        toml::from_str(&format!("[server]\nlisten = [\"tcp:{addr}\"]\n")).unwrap()
    }

    async fn bind_ephemeral() -> std::net::SocketAddr {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        addr
    }

    async fn wait_for_listener(addr: std::net::SocketAddr) {
        for _ in 0..50 {
            if TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn answers_dunno_for_a_basic_request() {
        let addr = bind_ephemeral().await;

        let state = Arc::new(AppState::new(test_config(addr)).unwrap());
        let shutdown = CancellationToken::new();

        let server_shutdown = shutdown.clone();
        let server_task = tokio::spawn(async move { run(state, server_shutdown).await });
        wait_for_listener(addr).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"request=smtpd_access_policy\nclient_address=192.0.2.10\n\n")
            .await
            .unwrap();

        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"action=dunno\n\n");

        shutdown.cancel();
        drop(stream);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), server_task).await;
    }

    #[tokio::test]
    async fn skip_addresses_bypasses_spf_check_entirely() {
        // Real HELO/sender values would normally trigger SPF evaluation (and
        // thus real DNS lookups); skip.addresses must short-circuit before
        // any of that happens.
        let addr = bind_ephemeral().await;
        let config: Config = toml::from_str(&format!(
            "[server]\nlisten = [\"tcp:{addr}\"]\n[skip]\naddresses = [\"192.0.2.0/24\"]\n"
        ))
        .unwrap();

        let state = Arc::new(AppState::new(config).unwrap());
        let shutdown = CancellationToken::new();

        let server_shutdown = shutdown.clone();
        let server_task = tokio::spawn(async move { run(state, server_shutdown).await });
        wait_for_listener(addr).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                b"request=smtpd_access_policy\nprotocol_state=RCPT\nhelo_name=mail.example.com\n\
                  sender=user@example.com\nclient_address=192.0.2.10\n\n",
            )
            .await
            .unwrap();

        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("response should arrive quickly, without any DNS lookups")
            .unwrap();
        assert_eq!(&buf[..n], b"action=dunno\n\n");

        shutdown.cancel();
        drop(stream);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), server_task).await;
    }
}
