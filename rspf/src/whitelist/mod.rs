use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

use thiserror::Error;

use crate::config::WhitelistConfig;
use crate::net::CidrSet;

/// Which whitelist entry caused a request to be exempted from SPF checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhitelistReason {
    Ip,
    Helo,
    Domain,
    DomainPtr,
}

#[derive(Debug, Error)]
pub enum WhitelistError {
    #[error("failed to read whitelist file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("whitelist file {path} line {line}: unrecognized entry {entry:?} (expected \"ip:\", \"helo:\", \"domain:\", or \"ptr:\" prefix)")]
    UnrecognizedEntry {
        path: String,
        line: usize,
        entry: String,
    },
    #[error("whitelist file {path} line {line}: invalid CIDR {value:?}: {source}")]
    InvalidCidr {
        path: String,
        line: usize,
        value: String,
        source: ipnet::AddrParseError,
    },
}

#[derive(Debug, Clone, Default)]
pub struct Whitelist {
    ips: CidrSet,
    helo_names: HashSet<String>,
    domains: Vec<String>,
    domains_ptr: Vec<String>,
}

impl Whitelist {
    /// Builds a whitelist from inline config plus any configured external
    /// files (one `prefix:value` entry per line; see [`Self::apply_file_line`]).
    pub fn load(cfg: &WhitelistConfig) -> Result<Self, WhitelistError> {
        let mut whitelist = Whitelist {
            ips: cfg.ips.clone(),
            helo_names: cfg
                .helo_names
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            domains: cfg.domains.iter().map(|s| s.to_ascii_lowercase()).collect(),
            domains_ptr: cfg
                .domains_ptr
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
        };

        for path in &cfg.files {
            whitelist.load_file(path)?;
        }

        Ok(whitelist)
    }

    fn load_file(&mut self, path: &Path) -> Result<(), WhitelistError> {
        let raw = std::fs::read_to_string(path).map_err(|source| WhitelistError::Read {
            path: path.display().to_string(),
            source,
        })?;

        for (idx, line) in raw.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            self.apply_file_line(path, idx + 1, line)?;
        }
        Ok(())
    }

    fn apply_file_line(
        &mut self,
        path: &Path,
        line_no: usize,
        line: &str,
    ) -> Result<(), WhitelistError> {
        let (prefix, value) =
            line.split_once(':')
                .ok_or_else(|| WhitelistError::UnrecognizedEntry {
                    path: path.display().to_string(),
                    line: line_no,
                    entry: line.to_string(),
                })?;
        let value = value.trim();

        match prefix {
            "ip" => {
                let net = value
                    .parse()
                    .map_err(|source| WhitelistError::InvalidCidr {
                        path: path.display().to_string(),
                        line: line_no,
                        value: value.to_string(),
                        source,
                    })?;
                self.ips.extend(std::iter::once(net));
            }
            "helo" => {
                self.helo_names.insert(value.to_ascii_lowercase());
            }
            "domain" => {
                self.domains.push(value.to_ascii_lowercase());
            }
            "ptr" => {
                self.domains_ptr.push(value.to_ascii_lowercase());
            }
            _ => {
                return Err(WhitelistError::UnrecognizedEntry {
                    path: path.display().to_string(),
                    line: line_no,
                    entry: line.to_string(),
                })
            }
        }
        Ok(())
    }

    /// Checks whether `ip`/`helo`/`mail_from_domain`/`reverse_client_name`
    /// match any whitelist entry, short-circuiting on the first match.
    pub fn matches(
        &self,
        ip: IpAddr,
        helo: &str,
        mail_from_domain: Option<&str>,
        reverse_client_name: Option<&str>,
    ) -> Option<WhitelistReason> {
        if self.ips.contains(ip) {
            return Some(WhitelistReason::Ip);
        }
        if self.helo_names.contains(&helo.to_ascii_lowercase()) {
            return Some(WhitelistReason::Helo);
        }
        if self.domains.iter().any(|d| matches_suffix(helo, d)) {
            return Some(WhitelistReason::Domain);
        }
        if let Some(domain) = mail_from_domain {
            if self.domains.iter().any(|d| matches_suffix(domain, d)) {
                return Some(WhitelistReason::Domain);
            }
        }
        if let Some(reverse) = reverse_client_name {
            if self.domains_ptr.iter().any(|d| matches_suffix(reverse, d)) {
                return Some(WhitelistReason::DomainPtr);
            }
        }
        None
    }
}

/// Whether `name` is exactly `suffix` or a subdomain of it (case-insensitive).
fn matches_suffix(name: &str, suffix: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == suffix || name.ends_with(&format!(".{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn cfg_with_ips(ips: &[&str]) -> WhitelistConfig {
        WhitelistConfig {
            ips: ips.iter().map(|s| s.parse().unwrap()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn matches_whitelisted_ip() {
        let wl = Whitelist::load(&cfg_with_ips(&["192.0.2.0/24"])).unwrap();
        assert_eq!(
            wl.matches("192.0.2.5".parse().unwrap(), "mail.example.com", None, None),
            Some(WhitelistReason::Ip)
        );
    }

    #[test]
    fn does_not_match_unlisted_ip() {
        let wl = Whitelist::load(&cfg_with_ips(&["192.0.2.0/24"])).unwrap();
        assert_eq!(
            wl.matches(
                "203.0.113.5".parse().unwrap(),
                "mail.example.com",
                None,
                None
            ),
            None
        );
    }

    #[test]
    fn matches_helo_name_case_insensitively() {
        let cfg = WhitelistConfig {
            helo_names: vec!["Mail.Example.Com".to_string()],
            ..Default::default()
        };
        let wl = Whitelist::load(&cfg).unwrap();
        assert_eq!(
            wl.matches(
                "203.0.113.5".parse().unwrap(),
                "mail.example.com",
                None,
                None
            ),
            Some(WhitelistReason::Helo)
        );
    }

    #[test]
    fn matches_domain_via_helo_suffix() {
        let cfg = WhitelistConfig {
            domains: vec!["example.com".to_string()],
            ..Default::default()
        };
        let wl = Whitelist::load(&cfg).unwrap();
        assert_eq!(
            wl.matches(
                "203.0.113.5".parse().unwrap(),
                "mail.example.com",
                None,
                None
            ),
            Some(WhitelistReason::Domain)
        );
    }

    #[test]
    fn matches_domain_via_mail_from_domain() {
        let cfg = WhitelistConfig {
            domains: vec!["example.com".to_string()],
            ..Default::default()
        };
        let wl = Whitelist::load(&cfg).unwrap();
        assert_eq!(
            wl.matches(
                "203.0.113.5".parse().unwrap(),
                "other.net",
                Some("sub.example.com"),
                None
            ),
            Some(WhitelistReason::Domain)
        );
    }

    #[test]
    fn domain_whitelist_does_not_match_lookalike_domain() {
        // "notexample.com" must not match a suffix rule for "example.com".
        let cfg = WhitelistConfig {
            domains: vec!["example.com".to_string()],
            ..Default::default()
        };
        let wl = Whitelist::load(&cfg).unwrap();
        assert_eq!(
            wl.matches(
                "203.0.113.5".parse().unwrap(),
                "mail.notexample.com",
                None,
                None
            ),
            None
        );
    }

    #[test]
    fn matches_ptr_domain_suffix() {
        let cfg = WhitelistConfig {
            domains_ptr: vec!["trusted.net".to_string()],
            ..Default::default()
        };
        let wl = Whitelist::load(&cfg).unwrap();
        assert_eq!(
            wl.matches(
                "203.0.113.5".parse().unwrap(),
                "mail.example.com",
                None,
                Some("mx1.trusted.net")
            ),
            Some(WhitelistReason::DomainPtr)
        );
    }

    #[test]
    fn loads_entries_from_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "# a comment").unwrap();
        writeln!(file, "ip:198.51.100.0/24").unwrap();
        writeln!(file, "helo:relay.partner.com").unwrap();
        writeln!(file, "domain:partner.com").unwrap();
        writeln!(file, "ptr:partner.com").unwrap();
        writeln!(file).unwrap(); // blank line should be skipped

        let cfg = WhitelistConfig {
            files: vec![file.path().to_path_buf()],
            ..Default::default()
        };
        let wl = Whitelist::load(&cfg).unwrap();

        assert_eq!(
            wl.matches("198.51.100.1".parse().unwrap(), "x", None, None),
            Some(WhitelistReason::Ip)
        );
        assert_eq!(
            wl.matches(
                "203.0.113.1".parse().unwrap(),
                "relay.partner.com",
                None,
                None
            ),
            Some(WhitelistReason::Helo)
        );
        assert_eq!(
            wl.matches(
                "203.0.113.1".parse().unwrap(),
                "mail.partner.com",
                None,
                None
            ),
            Some(WhitelistReason::Domain)
        );
        assert_eq!(
            wl.matches(
                "203.0.113.1".parse().unwrap(),
                "x",
                None,
                Some("mx.partner.com")
            ),
            Some(WhitelistReason::DomainPtr)
        );
    }

    #[test]
    fn rejects_unrecognized_file_entry() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "bogus:value").unwrap();

        let cfg = WhitelistConfig {
            files: vec![file.path().to_path_buf()],
            ..Default::default()
        };
        assert!(matches!(
            Whitelist::load(&cfg).unwrap_err(),
            WhitelistError::UnrecognizedEntry { .. }
        ));
    }

    #[test]
    fn rejects_invalid_cidr_in_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "ip:not-a-cidr").unwrap();

        let cfg = WhitelistConfig {
            files: vec![file.path().to_path_buf()],
            ..Default::default()
        };
        assert!(matches!(
            Whitelist::load(&cfg).unwrap_err(),
            WhitelistError::InvalidCidr { .. }
        ));
    }
}
