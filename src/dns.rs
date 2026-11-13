use std::collections::HashMap;
use std::net::IpAddr;

/// Optional, in-memory cached reverse DNS resolver.
pub struct DnsResolver {
    enabled: bool,
    cache: HashMap<IpAddr, Option<String>>,
}

impl DnsResolver {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            cache: HashMap::new(),
        }
    }

    pub fn resolve(&mut self, ip: &IpAddr) -> Option<String> {
        if !self.enabled {
            return None;
        }
        if let Some(cached) = self.cache.get(ip) {
            return cached.clone();
        }
        let resolved = dns_lookup::lookup_addr(ip)
            .ok()
            .filter(|name| name != &ip.to_string());
        self.cache.insert(*ip, resolved.clone());
        resolved
    }
}
