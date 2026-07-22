use std::net::IpAddr;

use ipnet::IpNet;
use serde::Deserialize;

/// A list of IP networks matched by containment, e.g. `skip_addresses`,
/// `whitelist.ips`, or `relay.trusted_relays`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct CidrSet(Vec<IpNet>);

impl CidrSet {
    pub fn new(nets: Vec<IpNet>) -> Self {
        Self(nets)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|net| net.contains(&ip))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &IpNet> {
        self.0.iter()
    }
}

impl FromIterator<IpNet> for CidrSet {
    fn from_iter<T: IntoIterator<Item = IpNet>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl Extend<IpNet> for CidrSet {
    fn extend<T: IntoIterator<Item = IpNet>>(&mut self, iter: T) {
        self.0.extend(iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(nets: &[&str]) -> CidrSet {
        CidrSet::new(nets.iter().map(|s| s.parse().unwrap()).collect())
    }

    #[test]
    fn matches_ipv4_cidr() {
        let s = set(&["192.0.2.0/24"]);
        assert!(s.contains("192.0.2.10".parse().unwrap()));
        assert!(!s.contains("192.0.3.10".parse().unwrap()));
    }

    #[test]
    fn matches_exact_host_slash_32() {
        let s = set(&["192.0.2.10/32"]);
        assert!(s.contains("192.0.2.10".parse().unwrap()));
        assert!(!s.contains("192.0.2.11".parse().unwrap()));
    }

    #[test]
    fn matches_ipv6_cidr() {
        let s = set(&["2001:db8::/32"]);
        assert!(s.contains("2001:db8::1".parse().unwrap()));
        assert!(!s.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn slash_zero_matches_everything_in_family() {
        let s = set(&["0.0.0.0/0"]);
        assert!(s.contains("8.8.8.8".parse().unwrap()));
        assert!(!s.contains("::1".parse().unwrap()));
    }

    #[test]
    fn empty_set_matches_nothing() {
        let s = CidrSet::default();
        assert!(s.is_empty());
        assert!(!s.contains("127.0.0.1".parse().unwrap()));
    }
}
