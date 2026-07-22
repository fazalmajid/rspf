use std::fmt;

/// The Postfix policy delegation response action.
///
/// See the `action_...` grammar in
/// <https://www.postfix.org/SMTPD_POLICY_README.html#protocol>.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// No opinion; let the remaining `smtpd_recipient_restrictions` decide.
    Dunno,
    /// Accept, but prepend this header (e.g. `Received-SPF: ...`) to the message.
    Prepend(String),
    /// Reject with an explicit SMTP reply, e.g. `"550 5.7.1 SPF check failed"`.
    Reject(String),
    /// Defer for now, but only if the mail would otherwise be accepted later.
    DeferIfPermit(String),
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Dunno => write!(f, "action=dunno"),
            Action::Prepend(header) => write!(f, "action=PREPEND {header}"),
            Action::Reject(reason) => write!(f, "action={reason}"),
            Action::DeferIfPermit(reason) => write!(f, "action=defer_if_permit {reason}"),
        }
    }
}

impl Action {
    /// Render the full wire response, including the blank-line terminator.
    pub fn to_wire(&self) -> String {
        format!("{self}\n\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dunno_wire_format() {
        assert_eq!(Action::Dunno.to_wire(), "action=dunno\n\n");
    }

    #[test]
    fn prepend_wire_format() {
        let action = Action::Prepend("Received-SPF: pass".to_string());
        assert_eq!(action.to_wire(), "action=PREPEND Received-SPF: pass\n\n");
    }

    #[test]
    fn reject_wire_format() {
        let action = Action::Reject("550 5.7.1 SPF check failed".to_string());
        assert_eq!(action.to_wire(), "action=550 5.7.1 SPF check failed\n\n");
    }

    #[test]
    fn defer_if_permit_wire_format() {
        let action = Action::DeferIfPermit("4.7.1 temporary DNS error".to_string());
        assert_eq!(
            action.to_wire(),
            "action=defer_if_permit 4.7.1 temporary DNS error\n\n"
        );
    }
}
