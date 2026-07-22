use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use hickory_resolver::error::ResolveError;
use hickory_resolver::TokioAsyncResolver;
use viaspf::lookup::{Lookup, LookupResult, Name};

/// A thin wrapper around `hickory_resolver::TokioAsyncResolver`.
///
/// `viaspf` already implements its `Lookup` trait directly for
/// `TokioAsyncResolver` (via its `hickory-resolver` feature), so this
/// wrapper's only job is to give tests a seam: production code depends on
/// `HickoryLookup`, tests depend on `MockLookup`, and both implement the
/// same `Lookup` trait `SpfEvaluator<L>` is generic over.
pub struct HickoryLookup(TokioAsyncResolver);

impl HickoryLookup {
    /// Builds a resolver from the system's `/etc/resolv.conf` (or platform
    /// equivalent).
    pub fn from_system_conf() -> Result<Self, ResolveError> {
        Ok(Self(TokioAsyncResolver::tokio_from_system_conf()?))
    }
}

#[async_trait]
impl Lookup for HickoryLookup {
    async fn lookup_a<'lookup, 'a>(&'lookup self, name: &'a Name) -> LookupResult<Vec<Ipv4Addr>> {
        self.0.lookup_a(name).await
    }

    async fn lookup_aaaa<'lookup, 'a>(
        &'lookup self,
        name: &'a Name,
    ) -> LookupResult<Vec<Ipv6Addr>> {
        self.0.lookup_aaaa(name).await
    }

    async fn lookup_mx<'lookup, 'a>(&'lookup self, name: &'a Name) -> LookupResult<Vec<Name>> {
        self.0.lookup_mx(name).await
    }

    async fn lookup_txt<'lookup, 'a>(&'lookup self, name: &'a Name) -> LookupResult<Vec<String>> {
        self.0.lookup_txt(name).await
    }

    async fn lookup_ptr<'lookup>(&'lookup self, ip: IpAddr) -> LookupResult<Vec<Name>> {
        self.0.lookup_ptr(ip).await
    }
}
