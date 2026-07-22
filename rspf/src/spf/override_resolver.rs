use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use async_trait::async_trait;
use viaspf::lookup::{Lookup, LookupResult, Name};

/// A `Lookup` decorator that intercepts TXT lookups for domains with a
/// configured override record, delegating everything else to the inner
/// resolver.
///
/// Applying this at the `Lookup` layer (rather than pre-fetching a domain's
/// top-level record before evaluation) means the override also takes effect
/// for domains reached transitively via `include:`/`redirect=`, since every
/// TXT lookup viaspf performs during evaluation passes through here.
pub struct OverrideLookup<L> {
    inner: L,
    /// Lowercased domain name -> raw SPF record text (e.g. `"v=spf1 -all"`).
    overrides: Arc<HashMap<String, String>>,
}

impl<L> OverrideLookup<L> {
    pub fn new(inner: L, overrides: Arc<HashMap<String, String>>) -> Self {
        Self { inner, overrides }
    }
}

#[async_trait]
impl<L: Lookup> Lookup for OverrideLookup<L> {
    async fn lookup_a<'lookup, 'a>(&'lookup self, name: &'a Name) -> LookupResult<Vec<Ipv4Addr>> {
        self.inner.lookup_a(name).await
    }

    async fn lookup_aaaa<'lookup, 'a>(
        &'lookup self,
        name: &'a Name,
    ) -> LookupResult<Vec<Ipv6Addr>> {
        self.inner.lookup_aaaa(name).await
    }

    async fn lookup_mx<'lookup, 'a>(&'lookup self, name: &'a Name) -> LookupResult<Vec<Name>> {
        self.inner.lookup_mx(name).await
    }

    async fn lookup_txt<'lookup, 'a>(&'lookup self, name: &'a Name) -> LookupResult<Vec<String>> {
        let key = name.to_string().to_ascii_lowercase();
        if let Some(record) = self.overrides.get(&key) {
            return Ok(vec![record.clone()]);
        }
        self.inner.lookup_txt(name).await
    }

    async fn lookup_ptr<'lookup>(&'lookup self, ip: IpAddr) -> LookupResult<Vec<Name>> {
        self.inner.lookup_ptr(ip).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spf::mock::MockLookup;

    fn overrides(pairs: &[(&str, &str)]) -> Arc<HashMap<String, String>> {
        Arc::new(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[tokio::test]
    async fn override_present_replaces_txt_lookup() {
        let inner = MockLookup::new().with_txt("example.com", vec!["v=spf1 -all".to_string()]);
        let lookup = OverrideLookup::new(inner, overrides(&[("example.com", "v=spf1 +all")]));

        let name = Name::new("example.com").unwrap();
        let txt = lookup.lookup_txt(&name).await.unwrap();
        assert_eq!(txt, vec!["v=spf1 +all".to_string()]);
    }

    #[tokio::test]
    async fn override_absent_falls_through_to_inner() {
        let inner = MockLookup::new().with_txt("example.com", vec!["v=spf1 -all".to_string()]);
        let lookup = OverrideLookup::new(inner, overrides(&[("other.com", "v=spf1 +all")]));

        let name = Name::new("example.com").unwrap();
        let txt = lookup.lookup_txt(&name).await.unwrap();
        assert_eq!(txt, vec!["v=spf1 -all".to_string()]);
    }

    #[tokio::test]
    async fn override_matching_is_case_insensitive() {
        let inner = MockLookup::new();
        let lookup = OverrideLookup::new(inner, overrides(&[("example.com", "v=spf1 +all")]));

        let name = Name::new("EXAMPLE.COM").unwrap();
        let txt = lookup.lookup_txt(&name).await.unwrap();
        assert_eq!(txt, vec!["v=spf1 +all".to_string()]);
    }

    #[tokio::test]
    async fn non_txt_lookups_always_delegate_to_inner() {
        let inner = MockLookup::new().with_a("example.com", vec!["192.0.2.1".parse().unwrap()]);
        let lookup = OverrideLookup::new(inner, overrides(&[("example.com", "v=spf1 +all")]));

        let name = Name::new("example.com").unwrap();
        let a = lookup.lookup_a(&name).await.unwrap();
        assert_eq!(a, vec!["192.0.2.1".parse::<Ipv4Addr>().unwrap()]);
    }
}
