use serde::Deserialize;

/// How to react to a given SPF identity's (HELO or MAIL FROM) result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectPolicy {
    /// Reject only on `Fail`.
    #[default]
    Fail,
    /// Reject on `Fail` or `SoftFail`.
    SoftFail,
    /// Reject on anything other than `Pass`.
    SpfNotPass,
    /// Never reject based on this identity's Fail/SoftFail/Neutral/None
    /// result. `permerror_reject`/`temperror_defer` still apply. The
    /// identity is still evaluated (DNS lookups run) and logged.
    Never,
    /// Like `Never`, but also suppresses `permerror_reject`/`temperror_defer`
    /// for this identity — its result can never affect the action, full
    /// stop. Note this does *not* skip the DNS evaluation or logging for
    /// this identity, only whether its result can drive a reject/defer.
    NoCheck,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Wrapper {
        value: RejectPolicy,
    }

    fn parse(raw: &str) -> RejectPolicy {
        toml::from_str::<Wrapper>(&format!("value = \"{raw}\""))
            .unwrap()
            .value
    }

    #[test]
    fn deserializes_snake_case_variants() {
        assert_eq!(parse("fail"), RejectPolicy::Fail);
        assert_eq!(parse("soft_fail"), RejectPolicy::SoftFail);
        assert_eq!(parse("spf_not_pass"), RejectPolicy::SpfNotPass);
        assert_eq!(parse("never"), RejectPolicy::Never);
        assert_eq!(parse("no_check"), RejectPolicy::NoCheck);
    }

    #[test]
    fn default_is_fail() {
        assert_eq!(RejectPolicy::default(), RejectPolicy::Fail);
    }
}
