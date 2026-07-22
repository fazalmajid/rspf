use tracing::Level;
use tracing_subscriber::EnvFilter;

use crate::config::LogLevel;

fn to_tracing_level(level: LogLevel) -> Option<Level> {
    match level {
        LogLevel::Off => None,
        LogLevel::Error => Some(Level::ERROR),
        LogLevel::Warn => Some(Level::WARN),
        LogLevel::Info => Some(Level::INFO),
        LogLevel::Debug => Some(Level::DEBUG),
        LogLevel::Trace => Some(Level::TRACE),
    }
}

fn filter_for(level: LogLevel) -> EnvFilter {
    match to_tracing_level(level) {
        Some(level) => EnvFilter::new(level.as_str().to_lowercase()),
        None => EnvFilter::new("off"),
    }
}

/// Initialize the global `tracing` subscriber, writing to stdout.
///
/// This daemon is meant to run under a process supervisor (e.g. daemontools)
/// that captures the child's stdout/stderr itself (typically piping it to
/// `multilog`), so logging always goes to stdout/stderr rather than syslog
/// or a log file the daemon manages itself.
pub fn init(level: LogLevel) {
    let filter = filter_for(level);
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_all_log_levels() {
        assert_eq!(to_tracing_level(LogLevel::Off), None);
        assert_eq!(to_tracing_level(LogLevel::Error), Some(Level::ERROR));
        assert_eq!(to_tracing_level(LogLevel::Warn), Some(Level::WARN));
        assert_eq!(to_tracing_level(LogLevel::Info), Some(Level::INFO));
        assert_eq!(to_tracing_level(LogLevel::Debug), Some(Level::DEBUG));
        assert_eq!(to_tracing_level(LogLevel::Trace), Some(Level::TRACE));
    }
}
