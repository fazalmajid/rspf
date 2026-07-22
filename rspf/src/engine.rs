use std::net::IpAddr;

use viaspf::SpfResult;

use crate::config::{Config, HeaderMode, MessageTemplates, RejectPolicy};
use crate::proto::Action;
use crate::spf::{build_received_spf, SpfOutcome};

/// Everything about the request that a rendered reject/defer message or
/// `Received-SPF` header may need to reference.
pub struct DecisionContext<'a> {
    pub ip: IpAddr,
    pub sender: &'a str,
    pub helo: &'a str,
    pub recipient: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Severity {
    None,
    Defer,
    Reject,
}

/// Turns the HELO and MAIL FROM SPF outcomes into a single Postfix policy
/// `Action`, per the configured [`RejectPolicy`] for each identity plus the
/// global `permerror_reject`/`temperror_defer` toggles.
///
/// MAIL FROM is the RFC 7208-recommended primary identity: on a tie, or
/// whenever HELO's severity is no worse than MAIL FROM's, MAIL FROM's
/// outcome and message are used. HELO can only *escalate* the response
/// (e.g. reject on a HELO failure even though MAIL FROM passed), never
/// downgrade a MAIL FROM reject/defer.
pub fn decide(
    cfg: &Config,
    helo: &SpfOutcome,
    mail_from: &SpfOutcome,
    ctx: &DecisionContext,
) -> Action {
    let helo_severity = classify_severity(
        cfg.policy.helo_reject,
        &helo.result,
        cfg.policy.permerror_reject,
        cfg.policy.temperror_defer,
    );
    let mail_from_severity = classify_severity(
        cfg.policy.mail_from_reject,
        &mail_from.result,
        cfg.policy.permerror_reject,
        cfg.policy.temperror_defer,
    );

    let (severity, responsible) = if helo_severity > mail_from_severity {
        (helo_severity, helo)
    } else {
        (mail_from_severity, mail_from)
    };

    match severity {
        Severity::Reject => Action::Reject(render_message(&cfg.messages, &responsible.result, ctx)),
        Severity::Defer => {
            Action::DeferIfPermit(render_message(&cfg.messages, &responsible.result, ctx))
        }
        Severity::None => match cfg.header.mode {
            HeaderMode::Spf => {
                let header = build_received_spf(
                    mail_from,
                    ctx.ip,
                    ctx.sender,
                    ctx.helo,
                    ctx.recipient,
                    &cfg.header,
                );
                Action::Prepend(format!("Received-SPF: {header}"))
            }
            HeaderMode::None => Action::Dunno,
        },
    }
}

fn classify_severity(
    policy: RejectPolicy,
    result: &SpfResult,
    permerror_reject: bool,
    temperror_defer: bool,
) -> Severity {
    if policy == RejectPolicy::NoCheck {
        return Severity::None;
    }

    match result {
        SpfResult::Permerror => {
            if permerror_reject {
                Severity::Reject
            } else {
                Severity::None
            }
        }
        SpfResult::Temperror => {
            if temperror_defer {
                Severity::Defer
            } else {
                Severity::None
            }
        }
        _ => match policy {
            RejectPolicy::Never | RejectPolicy::NoCheck => Severity::None,
            RejectPolicy::Fail => {
                if matches!(result, SpfResult::Fail(_)) {
                    Severity::Reject
                } else {
                    Severity::None
                }
            }
            RejectPolicy::SoftFail => {
                if matches!(result, SpfResult::Fail(_) | SpfResult::Softfail) {
                    Severity::Reject
                } else {
                    Severity::None
                }
            }
            RejectPolicy::SpfNotPass => {
                if matches!(result, SpfResult::Pass) {
                    Severity::None
                } else {
                    Severity::Reject
                }
            }
        },
    }
}

fn message_template<'a>(messages: &'a MessageTemplates, result: &SpfResult) -> &'a str {
    match result {
        SpfResult::Fail(_) => &messages.fail,
        SpfResult::Softfail => &messages.softfail,
        SpfResult::Neutral => &messages.neutral,
        SpfResult::None => &messages.none,
        SpfResult::Permerror => &messages.permerror,
        SpfResult::Temperror => &messages.temperror,
        // classify_severity never assigns Reject/Defer severity to a Pass
        // result, so this arm is unreachable in practice; return a generic
        // fallback rather than panicking on a network-facing code path.
        SpfResult::Pass => "550 5.7.1 SPF check failed",
    }
}

fn render_message(
    messages: &MessageTemplates,
    result: &SpfResult,
    ctx: &DecisionContext,
) -> String {
    message_template(messages, result)
        .replace("{result}", &result.to_string())
        .replace("{sender}", ctx.sender)
        .replace("{helo}", ctx.helo)
        .replace("{ip}", &ctx.ip.to_string())
        .replace("{recipient}", ctx.recipient)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HeaderConfig;
    use crate::spf::Identity;
    use viaspf::ExplanationString;

    fn config_with(
        helo_reject: RejectPolicy,
        mail_from_reject: RejectPolicy,
        permerror_reject: bool,
        temperror_defer: bool,
    ) -> Config {
        let mut cfg: Config =
            toml::from_str("[server]\nlisten = [\"tcp:127.0.0.1:10045\"]\n").unwrap();
        cfg.policy.helo_reject = helo_reject;
        cfg.policy.mail_from_reject = mail_from_reject;
        cfg.policy.permerror_reject = permerror_reject;
        cfg.policy.temperror_defer = temperror_defer;
        cfg
    }

    fn outcome(identity: Identity, result: SpfResult) -> SpfOutcome {
        SpfOutcome {
            identity,
            result,
            cause: None,
        }
    }

    fn ctx() -> DecisionContext<'static> {
        DecisionContext {
            ip: "192.0.2.1".parse().unwrap(),
            sender: "user@example.com",
            helo: "mail.example.com",
            recipient: "postmaster@ourdomain.com",
        }
    }

    fn fail() -> SpfResult {
        SpfResult::Fail(ExplanationString::Default)
    }

    // --- RejectPolicy::Fail (the default) ---

    #[test]
    fn fail_policy_rejects_on_fail() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::Fail, false, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, fail()),
            &ctx(),
        );
        assert!(matches!(action, Action::Reject(_)));
    }

    #[test]
    fn fail_policy_does_not_reject_on_softfail() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::Fail, false, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, SpfResult::Softfail),
            &ctx(),
        );
        assert!(matches!(action, Action::Prepend(_)));
    }

    // --- RejectPolicy::SoftFail ---

    #[test]
    fn softfail_policy_rejects_on_softfail() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::SoftFail, false, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, SpfResult::Softfail),
            &ctx(),
        );
        assert!(matches!(action, Action::Reject(_)));
    }

    // --- RejectPolicy::SpfNotPass ---

    #[test]
    fn spf_not_pass_rejects_on_neutral() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::SpfNotPass, false, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, SpfResult::Neutral),
            &ctx(),
        );
        assert!(matches!(action, Action::Reject(_)));
    }

    #[test]
    fn spf_not_pass_rejects_on_none() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::SpfNotPass, false, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, SpfResult::None),
            &ctx(),
        );
        assert!(matches!(action, Action::Reject(_)));
    }

    #[test]
    fn spf_not_pass_accepts_pass() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::SpfNotPass, false, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, SpfResult::Pass),
            &ctx(),
        );
        assert!(matches!(action, Action::Prepend(_)));
    }

    // --- RejectPolicy::Never ---

    #[test]
    fn never_policy_never_rejects_even_on_fail() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::Never, false, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, fail()),
            &ctx(),
        );
        assert!(matches!(action, Action::Prepend(_)));
    }

    // --- RejectPolicy::NoCheck ---

    #[test]
    fn no_check_policy_skips_even_on_fail() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::NoCheck, false, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, fail()),
            &ctx(),
        );
        assert!(matches!(action, Action::Prepend(_)));
    }

    // --- permerror_reject / temperror_defer toggles ---

    #[test]
    fn permerror_reject_off_by_default() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::Fail, false, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, SpfResult::Permerror),
            &ctx(),
        );
        assert!(matches!(action, Action::Prepend(_)));
    }

    #[test]
    fn permerror_reject_on_rejects() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::Fail, true, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, SpfResult::Permerror),
            &ctx(),
        );
        assert!(matches!(action, Action::Reject(_)));
    }

    #[test]
    fn temperror_defer_off_by_default() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::Fail, false, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, SpfResult::Temperror),
            &ctx(),
        );
        assert!(matches!(action, Action::Prepend(_)));
    }

    #[test]
    fn temperror_defer_on_defers() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::Fail, false, true);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, SpfResult::Temperror),
            &ctx(),
        );
        assert!(matches!(action, Action::DeferIfPermit(_)));
    }

    #[test]
    fn no_check_skips_permerror_reject_too() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::NoCheck, true, true);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, SpfResult::Permerror),
            &ctx(),
        );
        assert!(matches!(action, Action::Prepend(_)));
    }

    // --- HELO vs MAIL FROM precedence ---

    #[test]
    fn helo_escalates_reject_even_when_mail_from_passes() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::Fail, false, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, fail()),
            &outcome(Identity::MailFrom, SpfResult::Pass),
            &ctx(),
        );
        assert!(matches!(action, Action::Reject(_)));
    }

    #[test]
    fn mail_from_reject_is_not_downgraded_by_a_passing_helo() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::Fail, false, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, fail()),
            &ctx(),
        );
        assert!(matches!(action, Action::Reject(_)));
    }

    #[test]
    fn tie_prefers_mail_from_message() {
        // Both reject at the same severity; the rendered message should come
        // from mail_from (the primary identity), not helo.
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::Fail, false, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, fail()),
            &outcome(Identity::MailFrom, fail()),
            &ctx(),
        );
        match action {
            Action::Reject(msg) => assert!(msg.contains("user@example.com")),
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    // --- Header behavior ---

    #[test]
    fn header_mode_none_produces_dunno_instead_of_prepend() {
        let mut cfg = config_with(RejectPolicy::Fail, RejectPolicy::Fail, false, false);
        cfg.header.mode = HeaderMode::None;
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, SpfResult::Pass),
            &ctx(),
        );
        assert_eq!(action, Action::Dunno);
    }

    #[test]
    fn message_placeholders_are_substituted() {
        let cfg = config_with(RejectPolicy::Fail, RejectPolicy::Fail, false, false);
        let action = decide(
            &cfg,
            &outcome(Identity::Helo, SpfResult::Pass),
            &outcome(Identity::MailFrom, fail()),
            &ctx(),
        );
        match action {
            Action::Reject(msg) => {
                assert!(msg.contains("user@example.com"));
                assert!(msg.contains("192.0.2.1"));
                assert!(!msg.contains('{'));
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn header_config_default() {
        // Sanity check that HeaderConfig::default() is HeaderMode::Spf, so the
        // "prepend by default" tests above reflect the real default behavior.
        assert_eq!(HeaderConfig::default().mode, HeaderMode::Spf);
    }
}
