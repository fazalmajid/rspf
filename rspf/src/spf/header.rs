use std::net::IpAddr;

use viaspf::{ErrorCause, SpfResultCause};

use crate::config::HeaderConfig;

use super::evaluator::{Identity, SpfOutcome};

/// Builds a `Received-SPF:` header value per RFC 7208 §9.1, given the
/// context of the check that produced `outcome`.
///
/// The returned string does not include the `Received-SPF: ` field-name
/// prefix; callers (the Postfix `PREPEND` action) supply that separately.
pub fn build_received_spf(
    outcome: &SpfOutcome,
    ip: IpAddr,
    mail_from: &str,
    helo: &str,
    recipient: &str,
    cfg: &HeaderConfig,
) -> String {
    let identity = match outcome.identity {
        Identity::Helo => "helo",
        Identity::MailFrom => "mailfrom",
    };

    let receiver = if cfg.hide_receiver {
        "UNKNOWN".to_string()
    } else {
        recipient_domain(recipient, cfg.authserv_id.as_deref())
    };

    let comment = describe_cause(outcome, mail_from, ip);

    format!(
        "{result} ({comment}) client-ip={ip}; envelope-from=\"{mail_from}\"; helo={helo}; \
         receiver=\"{receiver}\"; identity={identity};",
        result = outcome.result,
    )
}

fn recipient_domain(recipient: &str, authserv_id: Option<&str>) -> String {
    if let Some(id) = authserv_id {
        return id.to_string();
    }
    recipient
        .rsplit_once('@')
        .map(|(_, domain)| domain.to_string())
        .unwrap_or_else(|| "UNKNOWN".to_string())
}

fn describe_cause(outcome: &SpfOutcome, mail_from: &str, ip: IpAddr) -> String {
    match &outcome.cause {
        Some(SpfResultCause::Match(mechanism)) => {
            format!(
                "domain of {mail_from} designates {ip} as {result}, matched \"{mechanism}\"",
                result = outcome.result
            )
        }
        Some(SpfResultCause::Error(cause)) => describe_error_cause(*cause),
        None => format!("domain of {mail_from} does not designate a policy for {ip}"),
    }
}

fn describe_error_cause(cause: ErrorCause) -> String {
    format!("{cause}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use viaspf::SpfResult;

    fn outcome(result: SpfResult, cause: Option<SpfResultCause>) -> SpfOutcome {
        SpfOutcome {
            identity: Identity::MailFrom,
            result,
            cause,
        }
    }

    #[test]
    fn includes_result_and_client_ip() {
        let header = build_received_spf(
            &outcome(SpfResult::Pass, None),
            "192.0.2.1".parse().unwrap(),
            "user@example.com",
            "mail.example.com",
            "postmaster@ourdomain.com",
            &HeaderConfig::default(),
        );
        assert!(header.starts_with("pass ("));
        assert!(header.contains("client-ip=192.0.2.1"));
        assert!(header.contains("envelope-from=\"user@example.com\""));
        assert!(header.contains("helo=mail.example.com"));
        assert!(header.contains("identity=mailfrom"));
    }

    #[test]
    fn hide_receiver_uses_unknown() {
        let cfg = HeaderConfig {
            hide_receiver: true,
            ..HeaderConfig::default()
        };
        let header = build_received_spf(
            &outcome(SpfResult::Pass, None),
            "192.0.2.1".parse().unwrap(),
            "user@example.com",
            "mail.example.com",
            "postmaster@ourdomain.com",
            &cfg,
        );
        assert!(header.contains("receiver=\"UNKNOWN\""));
    }

    #[test]
    fn authserv_id_overrides_receiver_domain() {
        let cfg = HeaderConfig {
            authserv_id: Some("mx.ourdomain.com".to_string()),
            ..HeaderConfig::default()
        };
        let header = build_received_spf(
            &outcome(SpfResult::Pass, None),
            "192.0.2.1".parse().unwrap(),
            "user@example.com",
            "mail.example.com",
            "postmaster@ourdomain.com",
            &cfg,
        );
        assert!(header.contains("receiver=\"mx.ourdomain.com\""));
    }

    #[test]
    fn error_cause_is_described() {
        let header = build_received_spf(
            &outcome(
                SpfResult::Temperror,
                Some(SpfResultCause::Error(ErrorCause::Timeout)),
            ),
            "192.0.2.1".parse().unwrap(),
            "user@example.com",
            "mail.example.com",
            "postmaster@ourdomain.com",
            &HeaderConfig::default(),
        );
        assert!(header.starts_with("temperror ("));
        assert!(header.contains("DNS lookup timed out"));
    }
}
