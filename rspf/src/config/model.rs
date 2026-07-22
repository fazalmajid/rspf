use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use serde::Deserialize;

use crate::net::CidrSet;

use super::policy::RejectPolicy;

/// A listener address: either a TCP socket or a Unix domain socket path.
///
/// Written in TOML as a string, e.g. `"tcp:127.0.0.1:10045"` or
/// `"unix:/run/rspf/policy.sock"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenAddr {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ListenAddrParseError {
    #[error("listen address {0:?} has no \"tcp:\" or \"unix:\" prefix")]
    MissingScheme(String),
    #[error("invalid tcp listen address {0:?}: {1}")]
    InvalidTcp(String, String),
    #[error("unix listen address has an empty path")]
    EmptyUnixPath,
}

impl FromStr for ListenAddr {
    type Err = ListenAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(rest) = s.strip_prefix("tcp:") {
            let addr = rest
                .parse::<SocketAddr>()
                .map_err(|e| ListenAddrParseError::InvalidTcp(rest.to_string(), e.to_string()))?;
            Ok(ListenAddr::Tcp(addr))
        } else if let Some(rest) = s.strip_prefix("unix:") {
            if rest.is_empty() {
                return Err(ListenAddrParseError::EmptyUnixPath);
            }
            Ok(ListenAddr::Unix(PathBuf::from(rest)))
        } else {
            Err(ListenAddrParseError::MissingScheme(s.to_string()))
        }
    }
}

impl fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListenAddr::Tcp(addr) => write!(f, "tcp:{addr}"),
            ListenAddr::Unix(path) => write!(f, "unix:{}", path.display()),
        }
    }
}

impl<'de> Deserialize<'de> for ListenAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: Vec<ListenAddr>,
    #[serde(default)]
    pub test_only: bool,
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Off,
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct LogConfig {
    #[serde(default)]
    pub level: LogLevel,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub helo_reject: RejectPolicy,
    #[serde(default)]
    pub mail_from_reject: RejectPolicy,
    #[serde(default)]
    pub permerror_reject: bool,
    #[serde(default)]
    pub temperror_defer: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SkipConfig {
    #[serde(default)]
    pub addresses: CidrSet,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WhitelistConfig {
    #[serde(default)]
    pub ips: CidrSet,
    #[serde(default)]
    pub helo_names: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub domains_ptr: Vec<String>,
    #[serde(default)]
    pub files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SpfConfig {
    #[serde(default = "default_lookup_timeout_secs")]
    pub lookup_timeout_secs: u64,
    #[serde(default = "default_void_limit")]
    pub void_limit: usize,
    #[serde(default = "default_max_lookups")]
    pub max_lookups: usize,
}

fn default_lookup_timeout_secs() -> u64 {
    20
}
fn default_void_limit() -> usize {
    2
}
fn default_max_lookups() -> usize {
    10
}

impl Default for SpfConfig {
    fn default() -> Self {
        Self {
            lookup_timeout_secs: default_lookup_timeout_secs(),
            void_limit: default_void_limit(),
            max_lookups: default_max_lookups(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SrsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub secrets: Vec<String>,
    #[serde(default = "default_srs_max_age_days")]
    pub max_age_days: u32,
}

fn default_srs_max_age_days() -> u32 {
    21
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RelayConfig {
    #[serde(default)]
    pub exempt_sasl_authenticated: bool,
    #[serde(default)]
    pub trusted_relays: CidrSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderMode {
    #[default]
    Spf,
    None,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct HeaderConfig {
    #[serde(default)]
    pub mode: HeaderMode,
    #[serde(default)]
    pub hide_receiver: bool,
    #[serde(default)]
    pub authserv_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MessageTemplates {
    #[serde(default = "default_fail_message")]
    pub fail: String,
    #[serde(default = "default_softfail_message")]
    pub softfail: String,
    #[serde(default = "default_neutral_message")]
    pub neutral: String,
    #[serde(default = "default_none_message")]
    pub none: String,
    #[serde(default = "default_permerror_message")]
    pub permerror: String,
    #[serde(default = "default_temperror_message")]
    pub temperror: String,
}

fn default_fail_message() -> String {
    "550 5.7.1 SPF check failed: {sender} is not allowed to send mail from {ip}".to_string()
}
fn default_softfail_message() -> String {
    "550 5.7.1 SPF check failed (softfail): {sender} is not allowed to send mail from {ip}"
        .to_string()
}
fn default_neutral_message() -> String {
    "550 5.7.1 SPF check neutral for {sender} from {ip}".to_string()
}
fn default_none_message() -> String {
    "550 5.7.1 SPF check found no record for {sender}".to_string()
}
fn default_permerror_message() -> String {
    "550 5.7.1 SPF check permanent error for {sender}".to_string()
}
fn default_temperror_message() -> String {
    "451 4.7.1 Temporary SPF error for {sender}, please try again later".to_string()
}

impl Default for MessageTemplates {
    fn default() -> Self {
        Self {
            fail: default_fail_message(),
            softfail: default_softfail_message(),
            neutral: default_neutral_message(),
            none: default_none_message(),
            permerror: default_permerror_message(),
            temperror: default_temperror_message(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub skip: SkipConfig,
    #[serde(default)]
    pub whitelist: WhitelistConfig,
    #[serde(default)]
    pub spf: SpfConfig,
    #[serde(default)]
    pub overrides: HashMap<String, String>,
    #[serde(default)]
    pub srs: SrsConfig,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default)]
    pub header: HeaderConfig,
    #[serde(default)]
    pub messages: MessageTemplates,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tcp_listen_addr() {
        assert_eq!(
            "tcp:127.0.0.1:10045".parse::<ListenAddr>().unwrap(),
            ListenAddr::Tcp("127.0.0.1:10045".parse().unwrap())
        );
    }

    #[test]
    fn parses_unix_listen_addr() {
        assert_eq!(
            "unix:/run/rspf/policy.sock".parse::<ListenAddr>().unwrap(),
            ListenAddr::Unix(PathBuf::from("/run/rspf/policy.sock"))
        );
    }

    #[test]
    fn rejects_missing_scheme() {
        assert_eq!(
            "127.0.0.1:10045".parse::<ListenAddr>().unwrap_err(),
            ListenAddrParseError::MissingScheme("127.0.0.1:10045".to_string())
        );
    }

    #[test]
    fn rejects_bad_tcp_addr() {
        assert!(matches!(
            "tcp:not-an-addr".parse::<ListenAddr>().unwrap_err(),
            ListenAddrParseError::InvalidTcp(_, _)
        ));
    }

    #[test]
    fn rejects_empty_unix_path() {
        assert_eq!(
            "unix:".parse::<ListenAddr>().unwrap_err(),
            ListenAddrParseError::EmptyUnixPath
        );
    }
}
