use std::path::Path;

use thiserror::Error;

use super::model::Config;

const KNOWN_MESSAGE_PLACEHOLDERS: &[&str] = &["result", "sender", "helo", "ip", "recipient"];

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("srs.enabled is true but srs.secrets is empty")]
    SrsEnabledWithoutSecrets,
    #[error("overrides.{domain}: invalid SPF record {record:?}: {source}")]
    InvalidOverrideRecord {
        domain: String,
        record: String,
        source: viaspf::record::ParseError,
    },
    #[error("no listen addresses configured (server.listen is empty)")]
    NoListenAddresses,
    #[error("message template {name:?} references unknown placeholder {{{placeholder}}}")]
    UnknownMessagePlaceholder { name: String, placeholder: String },
}

impl Config {
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let config: Config = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.display().to_string(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.listen.is_empty() {
            return Err(ConfigError::NoListenAddresses);
        }

        if self.srs.enabled && self.srs.secrets.is_empty() {
            return Err(ConfigError::SrsEnabledWithoutSecrets);
        }

        for (domain, record) in &self.overrides {
            record
                .parse::<viaspf::record::SpfRecord>()
                .map_err(|source| ConfigError::InvalidOverrideRecord {
                    domain: domain.clone(),
                    record: record.clone(),
                    source,
                })?;
        }

        for (name, template) in [
            ("fail", &self.messages.fail),
            ("softfail", &self.messages.softfail),
            ("neutral", &self.messages.neutral),
            ("none", &self.messages.none),
            ("permerror", &self.messages.permerror),
            ("temperror", &self.messages.temperror),
        ] {
            validate_placeholders(name, template)?;
        }

        Ok(())
    }
}

fn validate_placeholders(name: &str, template: &str) -> Result<(), ConfigError> {
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            break;
        };
        let placeholder = &after_open[..close];
        if !KNOWN_MESSAGE_PLACEHOLDERS.contains(&placeholder) {
            return Err(ConfigError::UnknownMessagePlaceholder {
                name: name.to_string(),
                placeholder: placeholder.to_string(),
            });
        }
        rest = &after_open[close + 1..];
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp_config(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file
    }

    #[test]
    fn loads_minimal_valid_config() {
        let file = write_temp_config(
            r#"
            [server]
            listen = ["tcp:127.0.0.1:10045"]
            "#,
        );
        let config = Config::load(file.path()).unwrap();
        assert_eq!(config.server.listen.len(), 1);
        assert_eq!(config.spf.void_limit, 2);
    }

    #[test]
    fn rejects_empty_listen_list() {
        let file = write_temp_config(
            r#"
            [server]
            listen = []
            "#,
        );
        assert!(matches!(
            Config::load(file.path()).unwrap_err(),
            ConfigError::NoListenAddresses
        ));
    }

    #[test]
    fn rejects_srs_enabled_without_secrets() {
        let file = write_temp_config(
            r#"
            [server]
            listen = ["tcp:127.0.0.1:10045"]
            [srs]
            enabled = true
            "#,
        );
        assert!(matches!(
            Config::load(file.path()).unwrap_err(),
            ConfigError::SrsEnabledWithoutSecrets
        ));
    }

    #[test]
    fn rejects_bad_override_record() {
        let file = write_temp_config(
            r#"
            [server]
            listen = ["tcp:127.0.0.1:10045"]
            [overrides]
            "example.com" = "not an spf record"
            "#,
        );
        assert!(matches!(
            Config::load(file.path()).unwrap_err(),
            ConfigError::InvalidOverrideRecord { domain, .. } if domain == "example.com"
        ));
    }

    #[test]
    fn accepts_valid_override_record() {
        let file = write_temp_config(
            r#"
            [server]
            listen = ["tcp:127.0.0.1:10045"]
            [overrides]
            "example.com" = "v=spf1 ip4:192.0.2.0/24 -all"
            "#,
        );
        let config = Config::load(file.path()).unwrap();
        assert_eq!(
            config.overrides.get("example.com").unwrap(),
            "v=spf1 ip4:192.0.2.0/24 -all"
        );
    }

    #[test]
    fn rejects_override_record_with_v_spf1_prefix_but_bad_syntax() {
        // A record starting with "v=spf1" but with an invalid mechanism must
        // still be rejected at load time, not deferred to request time.
        let file = write_temp_config(
            r#"
            [server]
            listen = ["tcp:127.0.0.1:10045"]
            [overrides]
            "example.com" = "v=spf1 this-is-not-valid-all"
            "#,
        );
        assert!(matches!(
            Config::load(file.path()).unwrap_err(),
            ConfigError::InvalidOverrideRecord { domain, .. } if domain == "example.com"
        ));
    }

    #[test]
    fn rejects_unknown_message_placeholder() {
        let file = write_temp_config(
            r#"
            [server]
            listen = ["tcp:127.0.0.1:10045"]
            [messages]
            fail = "550 5.7.1 {bogus}"
            "#,
        );
        assert!(matches!(
            Config::load(file.path()).unwrap_err(),
            ConfigError::UnknownMessagePlaceholder { name, placeholder }
                if name == "fail" && placeholder == "bogus"
        ));
    }

    #[test]
    fn accepts_known_message_placeholders() {
        let file = write_temp_config(
            r#"
            [server]
            listen = ["tcp:127.0.0.1:10045"]
            [messages]
            fail = "550 5.7.1 {sender} not allowed from {ip} for {recipient} ({helo}) [{result}]"
            "#,
        );
        assert!(Config::load(file.path()).is_ok());
    }
}
