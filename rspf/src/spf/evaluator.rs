use std::net::IpAddr;
use std::time::Duration;

use viaspf::lookup::Lookup;
use viaspf::{DomainName, Sender, SpfResult, SpfResultCause};

use crate::config::SpfConfig;

/// Which SMTP identity an [`SpfOutcome`] was computed for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    Helo,
    MailFrom,
}

/// The result of one SPF check (HELO or MAIL FROM), decoupled from `viaspf`
/// evaluation itself so `engine::decide` can be tested with hand-built
/// values and no DNS/viaspf dependency.
#[derive(Debug, Clone)]
pub struct SpfOutcome {
    pub identity: Identity,
    pub result: SpfResult,
    pub cause: Option<SpfResultCause>,
}

impl SpfOutcome {
    fn permerror(identity: Identity) -> Self {
        Self {
            identity,
            result: SpfResult::Permerror,
            cause: None,
        }
    }

    fn from_query_result(identity: Identity, result: viaspf::QueryResult) -> Self {
        Self {
            identity,
            result: result.spf_result,
            cause: result.cause,
        }
    }
}

pub struct SpfEvaluator<L> {
    lookup: L,
    config: viaspf::Config,
}

impl<L: Lookup> SpfEvaluator<L> {
    pub fn new(lookup: L, cfg: &SpfConfig) -> Self {
        let config = viaspf::Config::builder()
            .max_lookups(cfg.max_lookups)
            .max_void_lookups(cfg.void_limit)
            .timeout(Duration::from_secs(cfg.lookup_timeout_secs))
            .build();
        Self { lookup, config }
    }

    /// Checks the HELO/EHLO identity. A syntactically invalid `helo` domain
    /// evaluates to `Permerror` (RFC 7208 has no defined behavior for an
    /// unparseable identity; treating it as an error is the conservative
    /// choice pypolicyd-spf also makes).
    pub async fn check_helo(&self, ip: IpAddr, helo: &str) -> SpfOutcome {
        let sender = match Sender::from_domain(helo) {
            Ok(s) => s,
            Err(_) => return SpfOutcome::permerror(Identity::Helo),
        };
        let helo_domain = sender.domain().clone();
        let result =
            viaspf::evaluate_sender(&self.lookup, &self.config, ip, &sender, Some(&helo_domain))
                .await;
        SpfOutcome::from_query_result(Identity::Helo, result)
    }

    /// Checks the MAIL FROM identity. Per RFC 7208 §2.4, a null sender
    /// (`MAIL FROM:<>`, passed here as an empty string) is checked as
    /// `postmaster@<helo-domain>`.
    pub async fn check_mail_from(&self, ip: IpAddr, mail_from: &str, helo: &str) -> SpfOutcome {
        let sender = if mail_from.is_empty() {
            Sender::from_domain(helo)
        } else {
            Sender::from_address(mail_from)
        };
        let sender = match sender {
            Ok(s) => s,
            Err(_) => return SpfOutcome::permerror(Identity::MailFrom),
        };
        let helo_domain = DomainName::new(helo).ok();
        let result = viaspf::evaluate_sender(
            &self.lookup,
            &self.config,
            ip,
            &sender,
            helo_domain.as_ref(),
        )
        .await;
        SpfOutcome::from_query_result(Identity::MailFrom, result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spf::mock::MockLookup;

    fn cfg() -> SpfConfig {
        SpfConfig {
            lookup_timeout_secs: 5,
            void_limit: 2,
            max_lookups: 10,
        }
    }

    fn ip() -> IpAddr {
        "192.0.2.1".parse().unwrap()
    }

    #[tokio::test]
    async fn pass_via_ip4_mechanism() {
        let lookup = MockLookup::new().with_txt(
            "example.com",
            vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()],
        );
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator
            .check_mail_from(ip(), "user@example.com", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn fail_when_ip_not_listed() {
        let lookup = MockLookup::new().with_txt(
            "example.com",
            vec!["v=spf1 ip4:203.0.113.0/24 -all".to_string()],
        );
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator
            .check_mail_from(ip(), "user@example.com", "mail.example.com")
            .await;
        assert!(matches!(outcome.result, SpfResult::Fail(_)));
    }

    #[tokio::test]
    async fn softfail_result() {
        let lookup = MockLookup::new().with_txt(
            "example.com",
            vec!["v=spf1 ip4:203.0.113.0/24 ~all".to_string()],
        );
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator
            .check_mail_from(ip(), "user@example.com", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::Softfail);
    }

    #[tokio::test]
    async fn neutral_result() {
        let lookup = MockLookup::new().with_txt(
            "example.com",
            vec!["v=spf1 ip4:203.0.113.0/24 ?all".to_string()],
        );
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator
            .check_mail_from(ip(), "user@example.com", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::Neutral);
    }

    #[tokio::test]
    async fn none_when_no_spf_record() {
        let lookup = MockLookup::new(); // no txt record at all -> NXDOMAIN/no records
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator
            .check_mail_from(ip(), "user@example.com", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::None);
    }

    #[tokio::test]
    async fn permerror_on_unparsable_record() {
        let lookup = MockLookup::new().with_txt(
            "example.com",
            vec!["v=spf1 this-is-not-valid-all".to_string()],
        );
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator
            .check_mail_from(ip(), "user@example.com", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::Permerror);
    }

    #[tokio::test]
    async fn temperror_on_dns_timeout() {
        let lookup = MockLookup::new().with_timeout("example.com");
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator
            .check_mail_from(ip(), "user@example.com", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::Temperror);
    }

    #[tokio::test]
    async fn include_mechanism_chain() {
        let lookup = MockLookup::new()
            .with_txt(
                "example.com",
                vec!["v=spf1 include:_spf.example.net -all".to_string()],
            )
            .with_txt(
                "_spf.example.net",
                vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()],
            );
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator
            .check_mail_from(ip(), "user@example.com", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn redirect_modifier_chain() {
        let lookup = MockLookup::new()
            .with_txt(
                "example.com",
                vec!["v=spf1 redirect=_spf.example.net".to_string()],
            )
            .with_txt(
                "_spf.example.net",
                vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()],
            );
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator
            .check_mail_from(ip(), "user@example.com", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn void_lookup_limit_exceeded_is_permerror() {
        // Each of these mechanisms resolves to NXDOMAIN (a "void" lookup);
        // with void_limit=2 the third one should trip the limit.
        let lookup = MockLookup::new().with_txt(
            "example.com",
            vec![
                "v=spf1 a:void1.example.com a:void2.example.com a:void3.example.com -all"
                    .to_string(),
            ],
        );
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator
            .check_mail_from(ip(), "user@example.com", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::Permerror);
    }

    #[tokio::test]
    async fn pass_via_mx_mechanism() {
        let lookup = MockLookup::new()
            .with_txt("example.com", vec!["v=spf1 mx -all".to_string()])
            .with_mx("example.com", vec!["mail.example.com".to_string()])
            .with_a("mail.example.com", vec!["192.0.2.1".parse().unwrap()]);
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator
            .check_mail_from(ip(), "user@example.com", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn pass_via_ip6_mechanism() {
        let lookup = MockLookup::new().with_txt(
            "example.com",
            vec!["v=spf1 ip6:2001:db8::/32 -all".to_string()],
        );
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let v6_ip: IpAddr = "2001:db8::1".parse().unwrap();
        let outcome = evaluator
            .check_mail_from(v6_ip, "user@example.com", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn pass_via_a_mechanism_over_ipv6() {
        let lookup = MockLookup::new()
            .with_txt("example.com", vec!["v=spf1 a -all".to_string()])
            .with_aaaa("example.com", vec!["2001:db8::1".parse().unwrap()]);
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let v6_ip: IpAddr = "2001:db8::1".parse().unwrap();
        let outcome = evaluator
            .check_mail_from(v6_ip, "user@example.com", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn pass_via_ptr_mechanism() {
        let lookup = MockLookup::new()
            .with_txt("example.com", vec!["v=spf1 ptr -all".to_string()])
            .with_ptr(ip(), vec!["mail.example.com".to_string()])
            .with_a("mail.example.com", vec!["192.0.2.1".parse().unwrap()]);
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator
            .check_mail_from(ip(), "user@example.com", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn null_sender_uses_postmaster_at_helo_domain() {
        // MAIL FROM:<> must be evaluated as postmaster@<helo-domain>, per RFC 7208 §2.4.
        let lookup = MockLookup::new().with_txt(
            "mail.example.com",
            vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()],
        );
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator
            .check_mail_from(ip(), "", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::Pass);
    }

    #[tokio::test]
    async fn invalid_mail_from_is_permerror() {
        let lookup = MockLookup::new();
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator
            .check_mail_from(ip(), "not-an-email-address", "mail.example.com")
            .await;
        assert_eq!(outcome.result, SpfResult::Permerror);
    }

    #[tokio::test]
    async fn check_helo_evaluates_against_helo_domain() {
        let lookup = MockLookup::new().with_txt(
            "mail.example.com",
            vec!["v=spf1 ip4:192.0.2.0/24 -all".to_string()],
        );
        let evaluator = SpfEvaluator::new(lookup, &cfg());

        let outcome = evaluator.check_helo(ip(), "mail.example.com").await;
        assert_eq!(outcome.identity, Identity::Helo);
        assert_eq!(outcome.result, SpfResult::Pass);
    }
}
