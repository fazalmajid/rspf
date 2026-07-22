//! Mirrors the per-request SPF decision to syslog under the `mail`
//! facility — the same facility Postfix itself logs to, and formatted to
//! resemble Postfix's own log lines — so the two interleave in
//! `/var/log/mail.log` (or wherever your syslog routes that facility) and
//! can be correlated by queue ID. For example:
//!
//! ```text
//! Jul 22 19:27:42 host postfix/rspfd[12345]: 8045F2AB23: from=<user@example.com>, client=mail.example.com[192.0.2.10], helo=mail.example.com, spf_helo=none, spf_mailfrom=pass, status=permit (Received-SPF: pass (...))
//! ```
//!
//! This is in addition to, not instead of, the regular `tracing`-based
//! stdout logging (see [`crate::logging`]); it's a raw `libc::syslog(3)`
//! call independent of the `tracing` subscriber. A missing/unreachable
//! syslog daemon is not fatal — `syslog(3)` has no failure return value, so
//! this is inherently best-effort by design of the underlying C API.

use std::ffi::CString;
use std::net::IpAddr;
use std::sync::Once;

use viaspf::SpfResult;

use crate::proto::Action;

static INIT: Once = Once::new();

/// Opens the connection to syslog under the `mail` facility with identity
/// `"postfix/rspfd"` (so log lines read `postfix/rspfd[pid]: ...`, matching
/// how Postfix's own subprocesses tag their lines, e.g. `postfix/smtp[pid]`).
/// Idempotent; call once at startup before `log_evaluated_spf`.
pub fn init() {
    INIT.call_once(|| unsafe {
        libc::openlog(
            c"postfix/rspfd".as_ptr(),
            libc::LOG_PID | libc::LOG_NDELAY,
            libc::LOG_MAIL,
        );
    });
}

/// Mirrors one request's SPF decision to syslog (facility `mail`, level
/// `info`), in a Postfix-log-like `key=value, ...` style.
#[allow(clippy::too_many_arguments)]
pub fn log_evaluated_spf(
    queue_id: Option<&str>,
    client_ip: IpAddr,
    client_name: Option<&str>,
    helo: &str,
    sender: &str,
    helo_result: &SpfResult,
    mail_from_result: &SpfResult,
    action: &Action,
) {
    let queue_id = queue_id.unwrap_or("NOQUEUE");
    let client_name = client_name.unwrap_or("unknown");
    let (status, detail) = describe_action(action);

    let mut msg = format!(
        "{queue_id}: from=<{sender}>, client={client_name}[{client_ip}], helo={helo}, \
         spf_helo={helo_result}, spf_mailfrom={mail_from_result}, status={status}"
    );
    if let Some(detail) = detail {
        msg.push_str(" (");
        msg.push_str(detail);
        msg.push(')');
    }

    write_to_syslog(&sanitize(&msg));
}

/// Postfix-style status word plus an optional parenthesized detail (the
/// Received-SPF header text on permit, or the reject/defer reason).
fn describe_action(action: &Action) -> (&'static str, Option<&str>) {
    match action {
        Action::Dunno => ("permit", None),
        Action::Prepend(header) => ("permit", Some(header.as_str())),
        Action::Reject(reason) => ("reject", Some(reason.as_str())),
        Action::DeferIfPermit(reason) => ("defer", Some(reason.as_str())),
    }
}

/// Replaces control characters (notably CR/LF, which could otherwise be
/// used to inject fake additional syslog lines) with spaces. The message
/// embeds `helo`/`sender`/queue_id, which originate from the SMTP session
/// (and, transitively via message templates, so does the reject/defer
/// detail text), so none of it is fully trusted.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn write_to_syslog(msg: &str) {
    // `sanitize()` already maps any NUL byte (a control character) to a
    // space, so `msg` should never contain an interior NUL; bail out rather
    // than panic if that invariant is ever violated.
    let Ok(msg) = CString::new(msg) else {
        return;
    };
    // SAFETY: `msg` is a valid NUL-terminated C string for the duration of
    // this call, and the format string is a fixed "%s" literal — the
    // message content is passed only as syslog(3)'s vararg, never as (or
    // interpolated into) the format string itself, so it cannot be
    // interpreted as format specifiers.
    unsafe {
        libc::syslog(
            libc::LOG_MAIL | libc::LOG_INFO,
            c"%s".as_ptr(),
            msg.as_ptr(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_replaces_control_characters() {
        assert_eq!(sanitize("mail.example.com"), "mail.example.com");
        assert_eq!(sanitize("evil\r\ninjected: line"), "evil  injected: line");
        assert_eq!(sanitize("nul\0byte"), "nul byte");
    }

    #[test]
    fn describe_action_permit_with_no_detail() {
        assert_eq!(describe_action(&Action::Dunno), ("permit", None));
    }

    #[test]
    fn describe_action_permit_with_header_detail() {
        let action = Action::Prepend("Received-SPF: pass".to_string());
        assert_eq!(
            describe_action(&action),
            ("permit", Some("Received-SPF: pass"))
        );
    }

    #[test]
    fn describe_action_reject_with_reason() {
        let action = Action::Reject("550 5.7.1 denied".to_string());
        assert_eq!(
            describe_action(&action),
            ("reject", Some("550 5.7.1 denied"))
        );
    }

    #[test]
    fn describe_action_defer_with_reason() {
        let action = Action::DeferIfPermit("4.7.1 try later".to_string());
        assert_eq!(describe_action(&action), ("defer", Some("4.7.1 try later")));
    }
}
