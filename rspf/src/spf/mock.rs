//! An in-memory `Lookup` implementation for tests.
//!
//! Because `SpfEvaluator<L>` and `viaspf::evaluate_sender` are generic over
//! `L: Lookup`, plugging this in exercises *real* `viaspf` mechanism
//! evaluation (`include:`, `redirect=`, `a`, `mx`, `ip4`, `-all`, void-lookup
//! limits, ...) deterministically, without any network access.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use viaspf::lookup::{Lookup, LookupError, LookupResult, Name};

#[derive(Debug, Default, Clone)]
pub struct MockLookup {
    txt: HashMap<String, Vec<String>>,
    a: HashMap<String, Vec<Ipv4Addr>>,
    aaaa: HashMap<String, Vec<Ipv6Addr>>,
    mx: HashMap<String, Vec<String>>,
    ptr: HashMap<IpAddr, Vec<String>>,
    /// Names that should return `LookupError::Timeout` instead of a normal
    /// (possibly empty/NXDOMAIN) result, to simulate DNS unavailability.
    timeouts: Vec<String>,
}

fn key(name: &Name) -> String {
    name.to_string().to_ascii_lowercase()
}

impl MockLookup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_txt(mut self, name: &str, records: Vec<String>) -> Self {
        self.txt.insert(name.to_ascii_lowercase(), records);
        self
    }

    pub fn with_a(mut self, name: &str, addrs: Vec<Ipv4Addr>) -> Self {
        self.a.insert(name.to_ascii_lowercase(), addrs);
        self
    }

    pub fn with_aaaa(mut self, name: &str, addrs: Vec<Ipv6Addr>) -> Self {
        self.aaaa.insert(name.to_ascii_lowercase(), addrs);
        self
    }

    pub fn with_mx(mut self, name: &str, exchanges: Vec<String>) -> Self {
        self.mx.insert(name.to_ascii_lowercase(), exchanges);
        self
    }

    pub fn with_ptr(mut self, ip: IpAddr, names: Vec<String>) -> Self {
        self.ptr.insert(ip, names);
        self
    }

    pub fn with_timeout(mut self, name: &str) -> Self {
        self.timeouts.push(name.to_ascii_lowercase());
        self
    }
}

#[async_trait]
impl Lookup for MockLookup {
    async fn lookup_a<'lookup, 'a>(&'lookup self, name: &'a Name) -> LookupResult<Vec<Ipv4Addr>> {
        let key = key(name);
        if self.timeouts.contains(&key) {
            return Err(LookupError::Timeout);
        }
        self.a.get(&key).cloned().ok_or(LookupError::NoRecords)
    }

    async fn lookup_aaaa<'lookup, 'a>(
        &'lookup self,
        name: &'a Name,
    ) -> LookupResult<Vec<Ipv6Addr>> {
        let key = key(name);
        if self.timeouts.contains(&key) {
            return Err(LookupError::Timeout);
        }
        self.aaaa.get(&key).cloned().ok_or(LookupError::NoRecords)
    }

    async fn lookup_mx<'lookup, 'a>(&'lookup self, name: &'a Name) -> LookupResult<Vec<Name>> {
        let key = key(name);
        if self.timeouts.contains(&key) {
            return Err(LookupError::Timeout);
        }
        self.mx
            .get(&key)
            .ok_or(LookupError::NoRecords)?
            .iter()
            .map(|n| Name::new(n).map_err(|_| LookupError::Dns(None)))
            .collect()
    }

    async fn lookup_txt<'lookup, 'a>(&'lookup self, name: &'a Name) -> LookupResult<Vec<String>> {
        let key = key(name);
        if self.timeouts.contains(&key) {
            return Err(LookupError::Timeout);
        }
        self.txt.get(&key).cloned().ok_or(LookupError::NoRecords)
    }

    async fn lookup_ptr<'lookup>(&'lookup self, ip: IpAddr) -> LookupResult<Vec<Name>> {
        self.ptr
            .get(&ip)
            .ok_or(LookupError::NoRecords)?
            .iter()
            .map(|n| Name::new(n).map_err(|_| LookupError::Dns(None)))
            .collect()
    }
}
