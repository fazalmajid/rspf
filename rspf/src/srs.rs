//! SRS0 envelope-sender unwrapping (RFC forwarding via the Sender Rewriting
//! Scheme, as produced by relays such as postsrsd/libsrs2).
//!
//! This is *not* a pypolicyd-spf feature: forwarded mail otherwise fails SPF
//! because the forwarding relay's IP isn't authorized for the original
//! sender's domain, and SRS exists specifically to let the forwarder rewrite
//! the envelope sender to its own domain so SPF passes at the forwarding
//! hop. Unwrapping it here lets us instead evaluate SPF against the
//! *original* sender when the rewrite can be verified as genuine.
//!
//! Format: `SRS0=HHH=TT=domain=local@rewrite-domain`, where `HHH` is a
//! truncated base64-encoded `HMAC-SHA1(secret, "TT=domain=local")` and `TT`
//! is a 2-character base32 encoding of the day-of-rewrite modulo 1024 days.
//!
//! **Security-critical**: `HHH` MUST be verified against the configured
//! secret(s) before the embedded domain is trusted. Parsing `SRS0=...=
//! attacker.com=user@ourdomain.com` without verifying the hash would let an
//! attacker forge an envelope sender that evaluates SPF against a domain of
//! their own choosing (most likely one with a permissive or absent SPF
//! record), fully defeating the check. An unrecognized or invalid hash must
//! therefore fall through to evaluating the literal, as-received sender
//! (fail-safe), never an automatic pass.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::config::SrsConfig;

type HmacSha1 = Hmac<Sha1>;

const BASE32_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
const HASH_LEN_CHARS: usize = 4;
const DAYS_PER_CYCLE: u32 = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrsUnwrap {
    /// `sender` was not an `SRS0=` address at all.
    NotSrs,
    /// A verified rewrite; SPF should be evaluated against this address
    /// instead of the literal envelope sender.
    Valid { original_sender: String },
    /// Looked like `SRS0=...` but the hash didn't match any configured
    /// secret (or the timestamp couldn't be parsed). Treat as not-SRS.
    InvalidHash,
    /// Hash verified, but the embedded timestamp is older than
    /// `max_age_days`. Treat as not-SRS.
    Expired,
}

/// Attempts to unwrap `raw_sender` as an SRS0 address, verifying the hash
/// against `cfg.secrets` (tried in order, to support secret rotation).
pub fn try_unwrap(raw_sender: &str, cfg: &SrsConfig) -> SrsUnwrap {
    if !cfg.enabled {
        return SrsUnwrap::NotSrs;
    }

    let Some(rest) = raw_sender.strip_prefix("SRS0=") else {
        return SrsUnwrap::NotSrs;
    };
    let Some((payload, _rewrite_domain)) = rest.split_once('@') else {
        return SrsUnwrap::NotSrs;
    };

    let mut parts = payload.splitn(4, '=');
    let (Some(hash), Some(timestamp), Some(domain), Some(local)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return SrsUnwrap::NotSrs;
    };

    let hash_ok = cfg
        .secrets
        .iter()
        .any(|secret| compute_hash(secret, timestamp, domain, local).as_deref() == Some(hash));
    if !hash_ok {
        return SrsUnwrap::InvalidHash;
    }

    let Some(decoded_ts) = decode_timestamp(timestamp) else {
        return SrsUnwrap::InvalidHash;
    };
    if age_in_days(decoded_ts) > cfg.max_age_days {
        return SrsUnwrap::Expired;
    }

    SrsUnwrap::Valid {
        original_sender: format!("{local}@{domain}"),
    }
}

fn compute_hash(secret: &str, timestamp: &str, domain: &str, local: &str) -> Option<String> {
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(format!("{timestamp}={domain}={local}").as_bytes());
    let digest = mac.finalize().into_bytes();
    let encoded = BASE64.encode(digest);
    Some(encoded.chars().take(HASH_LEN_CHARS).collect())
}

fn decode_timestamp(s: &str) -> Option<u32> {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() != 2 {
        return None;
    }
    let mut val = 0u32;
    for c in chars {
        let digit = BASE32_ALPHABET
            .iter()
            .position(|&b| (b as char).eq_ignore_ascii_case(&c))?;
        val = val * 32 + digit as u32;
    }
    Some(val)
}

/// Age in days of a decoded (mod-1024) timestamp relative to now, handling
/// the 1024-day wraparound.
fn age_in_days(decoded_ts: u32) -> u32 {
    let now_days = current_days_since_epoch() % DAYS_PER_CYCLE as u64;
    (now_days as i64 - decoded_ts as i64).rem_euclid(DAYS_PER_CYCLE as i64) as u32
}

fn current_days_since_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_secs()
        / 86400
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_timestamp(days_since_epoch: u64) -> String {
        let val = (days_since_epoch % DAYS_PER_CYCLE as u64) as u32;
        let hi = BASE32_ALPHABET[(val / 32) as usize] as char;
        let lo = BASE32_ALPHABET[(val % 32) as usize] as char;
        format!("{hi}{lo}")
    }

    fn cfg(secrets: &[&str], max_age_days: u32) -> SrsConfig {
        SrsConfig {
            enabled: true,
            secrets: secrets.iter().map(|s| s.to_string()).collect(),
            max_age_days,
        }
    }

    fn make_srs_address(secret: &str, days_since_epoch: u64, domain: &str, local: &str) -> String {
        let timestamp = encode_timestamp(days_since_epoch);
        let hash = compute_hash(secret, &timestamp, domain, local).unwrap();
        format!("SRS0={hash}={timestamp}={domain}={local}@relay.example.net")
    }

    #[test]
    fn not_srs_when_disabled() {
        let mut c = cfg(&["secret"], 21);
        c.enabled = false;
        let addr = make_srs_address("secret", current_days_since_epoch(), "example.com", "user");
        assert_eq!(try_unwrap(&addr, &c), SrsUnwrap::NotSrs);
    }

    #[test]
    fn not_srs_for_ordinary_address() {
        assert_eq!(
            try_unwrap("user@example.com", &cfg(&["secret"], 21)),
            SrsUnwrap::NotSrs
        );
    }

    #[test]
    fn valid_srs_address_unwraps_to_original_sender() {
        let addr = make_srs_address("secret", current_days_since_epoch(), "example.com", "user");
        assert_eq!(
            try_unwrap(&addr, &cfg(&["secret"], 21)),
            SrsUnwrap::Valid {
                original_sender: "user@example.com".to_string()
            }
        );
    }

    #[test]
    fn tampered_domain_fails_hash_verification() {
        let addr = make_srs_address("secret", current_days_since_epoch(), "example.com", "user");
        // An attacker swaps in a different domain after the fact; the hash
        // no longer matches, so this must NOT be trusted as a valid rewrite.
        let tampered = addr.replace("example.com", "attacker.com");
        assert_eq!(
            try_unwrap(&tampered, &cfg(&["secret"], 21)),
            SrsUnwrap::InvalidHash
        );
    }

    #[test]
    fn wrong_secret_fails_hash_verification() {
        let addr = make_srs_address("secret", current_days_since_epoch(), "example.com", "user");
        assert_eq!(
            try_unwrap(&addr, &cfg(&["wrong-secret"], 21)),
            SrsUnwrap::InvalidHash
        );
    }

    #[test]
    fn secret_rotation_tries_each_configured_secret() {
        let addr = make_srs_address(
            "new-secret",
            current_days_since_epoch(),
            "example.com",
            "user",
        );
        assert_eq!(
            try_unwrap(&addr, &cfg(&["old-secret", "new-secret"], 21)),
            SrsUnwrap::Valid {
                original_sender: "user@example.com".to_string()
            }
        );
    }

    #[test]
    fn expired_timestamp_is_rejected() {
        let old_days = current_days_since_epoch().saturating_sub(30);
        let addr = make_srs_address("secret", old_days, "example.com", "user");
        assert_eq!(try_unwrap(&addr, &cfg(&["secret"], 21)), SrsUnwrap::Expired);
    }

    #[test]
    fn within_max_age_is_accepted() {
        let recent_days = current_days_since_epoch().saturating_sub(5);
        let addr = make_srs_address("secret", recent_days, "example.com", "user");
        assert_eq!(
            try_unwrap(&addr, &cfg(&["secret"], 21)),
            SrsUnwrap::Valid {
                original_sender: "user@example.com".to_string()
            }
        );
    }

    #[test]
    fn malformed_srs_prefix_without_enough_parts_is_not_srs() {
        assert_eq!(
            try_unwrap("SRS0=onlyonepart@relay.example.net", &cfg(&["secret"], 21)),
            SrsUnwrap::NotSrs
        );
    }

    #[test]
    fn timestamp_roundtrip() {
        for day in [0u64, 1, 500, 1023, 1024, 2000, 100_000] {
            let encoded = encode_timestamp(day);
            let decoded = decode_timestamp(&encoded).unwrap();
            assert_eq!(decoded, (day % DAYS_PER_CYCLE as u64) as u32);
        }
    }
}
