mod load;
mod model;
mod policy;

pub use load::ConfigError;
pub use model::{
    Config, HeaderConfig, HeaderMode, ListenAddr, ListenAddrParseError, LogConfig, LogLevel,
    MessageTemplates, PolicyConfig, RelayConfig, ServerConfig, SkipConfig, SpfConfig, SrsConfig,
    WhitelistConfig,
};
pub use policy::RejectPolicy;

/// A fully commented example config, identical to `config/rspf.toml.example`
/// in the repo (included verbatim so the two can never drift apart).
pub const EXAMPLE_TOML: &str = include_str!("../../../config/rspf.toml.example");

#[cfg(test)]
mod example_tests {
    use super::*;

    #[test]
    fn example_toml_parses_and_validates() {
        let config: Config = toml::from_str(EXAMPLE_TOML).expect("example config must parse");
        config.validate().expect("example config must validate");
    }
}
