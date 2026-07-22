use std::collections::HashMap;
use std::net::IpAddr;

use thiserror::Error;

/// A single Postfix policy delegation request (one "attribute=value" block).
///
/// See <https://www.postfix.org/SMTPD_POLICY_README.html> for the full
/// attribute list. Only the attributes this daemon actually consults get a
/// dedicated field; everything else lands in `extra` so unknown/unused
/// attributes never cause a parse failure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyRequest {
    pub request: Option<String>,
    pub protocol_state: Option<String>,
    pub protocol_name: Option<String>,
    pub helo_name: Option<String>,
    pub queue_id: Option<String>,
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub client_address: Option<String>,
    pub client_name: Option<String>,
    pub reverse_client_name: Option<String>,
    pub instance: Option<String>,
    pub sasl_username: Option<String>,
    pub extra: HashMap<String, String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RequestParseError {
    #[error("malformed attribute line (missing '='): {0:?}")]
    MalformedLine(String),
    #[error("empty request (no attribute lines before terminator)")]
    EmptyRequest,
    #[error("client_address attribute is missing")]
    MissingClientAddress,
    #[error("client_address {0:?} is not a valid IP address")]
    InvalidClientAddress(String),
}

impl PolicyRequest {
    /// Parse a request from its raw `attr=value` lines (terminator already
    /// stripped by the caller/codec).
    pub fn from_lines(lines: &[String]) -> Result<Self, RequestParseError> {
        if lines.is_empty() {
            return Err(RequestParseError::EmptyRequest);
        }

        let mut req = PolicyRequest::default();
        for line in lines {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| RequestParseError::MalformedLine(line.clone()))?;
            match key {
                "request" => req.request = Some(value.to_string()),
                "protocol_state" => req.protocol_state = Some(value.to_string()),
                "protocol_name" => req.protocol_name = Some(value.to_string()),
                "helo_name" => req.helo_name = Some(value.to_string()),
                "queue_id" => req.queue_id = Some(value.to_string()),
                "sender" => req.sender = Some(value.to_string()),
                "recipient" => req.recipient = Some(value.to_string()),
                "client_address" => req.client_address = Some(value.to_string()),
                "client_name" => req.client_name = Some(value.to_string()),
                "reverse_client_name" => req.reverse_client_name = Some(value.to_string()),
                "instance" => req.instance = Some(value.to_string()),
                "sasl_username" => req.sasl_username = Some(value.to_string()),
                other => {
                    req.extra.insert(other.to_string(), value.to_string());
                }
            }
        }
        Ok(req)
    }

    /// Parsed `client_address`, the IP this request's SPF check runs against.
    pub fn client_ip(&self) -> Result<IpAddr, RequestParseError> {
        let raw = self
            .client_address
            .as_deref()
            .ok_or(RequestParseError::MissingClientAddress)?;
        raw.parse()
            .map_err(|_| RequestParseError::InvalidClientAddress(raw.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_known_attributes() {
        let req = PolicyRequest::from_lines(&lines(&[
            "request=smtpd_access_policy",
            "protocol_state=RCPT",
            "helo_name=mail.example.com",
            "sender=user@example.com",
            "recipient=postmaster@ourdomain.com",
            "client_address=192.0.2.10",
            "instance=123.456.7",
        ]))
        .unwrap();

        assert_eq!(req.request.as_deref(), Some("smtpd_access_policy"));
        assert_eq!(req.protocol_state.as_deref(), Some("RCPT"));
        assert_eq!(req.helo_name.as_deref(), Some("mail.example.com"));
        assert_eq!(req.sender.as_deref(), Some("user@example.com"));
        assert_eq!(req.client_address.as_deref(), Some("192.0.2.10"));
        assert_eq!(
            req.client_ip().unwrap(),
            "192.0.2.10".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn unknown_attributes_go_to_extra() {
        let req = PolicyRequest::from_lines(&lines(&["sasl_method=plain", "size=1024"])).unwrap();
        assert_eq!(req.extra.get("sasl_method"), Some(&"plain".to_string()));
        assert_eq!(req.extra.get("size"), Some(&"1024".to_string()));
    }

    #[test]
    fn empty_value_is_allowed() {
        // Null sender (MAIL FROM:<>) arrives as "sender=" with an empty value.
        let req = PolicyRequest::from_lines(&lines(&["sender="])).unwrap();
        assert_eq!(req.sender.as_deref(), Some(""));
    }

    #[test]
    fn rejects_line_without_equals() {
        let err = PolicyRequest::from_lines(&lines(&["not_a_kv_pair"])).unwrap_err();
        assert_eq!(
            err,
            RequestParseError::MalformedLine("not_a_kv_pair".to_string())
        );
    }

    #[test]
    fn rejects_empty_request() {
        let err = PolicyRequest::from_lines(&[]).unwrap_err();
        assert_eq!(err, RequestParseError::EmptyRequest);
    }

    #[test]
    fn client_ip_missing() {
        let req = PolicyRequest::from_lines(&lines(&["sender=a@b.com"])).unwrap();
        assert_eq!(
            req.client_ip().unwrap_err(),
            RequestParseError::MissingClientAddress
        );
    }

    #[test]
    fn client_ip_invalid() {
        let req = PolicyRequest::from_lines(&lines(&["client_address=not-an-ip"])).unwrap();
        assert_eq!(
            req.client_ip().unwrap_err(),
            RequestParseError::InvalidClientAddress("not-an-ip".to_string())
        );
    }

    #[test]
    fn parses_ipv6_client_address() {
        let req = PolicyRequest::from_lines(&lines(&["client_address=2001:db8::1"])).unwrap();
        assert_eq!(
            req.client_ip().unwrap(),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }
}
