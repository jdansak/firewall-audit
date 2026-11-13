use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Inbound,
    Outbound,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Inbound => write!(f, "inbound"),
            Direction::Outbound => write!(f, "outbound"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl Protocol {
    #[allow(dead_code)]
    pub fn from_ip_proto(proto: u8) -> Self {
        match proto {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 | 58 => Protocol::Icmp,
            other => Protocol::Other(other),
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Other(p) => write!(f, "proto-{p}"),
        }
    }
}

/// Raw connection event emitted by an OS kernel event collector.
#[derive(Debug, Clone)]
pub struct RawConnectionEvent {
    pub direction: Direction,
    pub protocol: Protocol,
    pub interface: Option<String>,
    pub local_ip: IpAddr,
    pub local_port: u16,
    pub remote_ip: IpAddr,
    pub remote_port: u16,
    pub application: Option<String>,
    pub executable_path: Option<String>,
}

/// Deduplication key representing a minimal firewall pinhole rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub direction: String,
    pub protocol: String,
    pub interface: String,
    pub local_port: String,
    pub remote_ip: String,
    pub remote_port: String,
    pub executable_path: String,
}

/// Persisted CSV row representing a unique firewall rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub direction: String,
    pub protocol: String,
    pub interface: String,
    pub local_port: String,
    pub remote_ip: String,
    pub remote_port: String,
    pub application: String,
    pub executable_path: String,
    pub dns_name: String,
}

impl AuditRecord {
    pub fn from_raw(
        event: &RawConnectionEvent,
        resolved_interface: &str,
        dns_name: Option<String>,
        keep_ephemeral_ports: bool,
    ) -> Self {
        let (local_port, remote_port) = if keep_ephemeral_ports {
            (event.local_port.to_string(), event.remote_port.to_string())
        } else {
            match event.direction {
                Direction::Outbound => ("*".to_string(), event.remote_port.to_string()),
                Direction::Inbound => (event.local_port.to_string(), "*".to_string()),
            }
        };

        let executable_path = event
            .executable_path
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown")
            .to_string();

        let application = event
            .application
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| {
                std::path::Path::new(&executable_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            });

        AuditRecord {
            direction: event.direction.to_string(),
            protocol: event.protocol.to_string(),
            interface: resolved_interface.to_string(),
            local_port,
            remote_ip: event.remote_ip.to_string(),
            remote_port,
            application,
            executable_path,
            dns_name: dns_name.unwrap_or_default(),
        }
    }

    pub fn flow_key(&self) -> FlowKey {
        FlowKey {
            direction: self.direction.clone(),
            protocol: self.protocol.clone(),
            interface: self.interface.clone(),
            local_port: self.local_port.clone(),
            remote_ip: self.remote_ip.clone(),
            remote_port: self.remote_port.clone(),
            executable_path: self.executable_path.clone(),
        }
    }
}

/// Returns true if the IP address is loopback (`127.0.0.0/8`, `::1`, `::ffff:127.x.x.x`)
/// or unspecified (`0.0.0.0`, `::`, `::ffff:0.0.0.0`).
pub fn is_loopback_or_unspecified(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                return mapped_v4.is_loopback() || mapped_v4.is_unspecified();
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn sample_event(direction: Direction) -> RawConnectionEvent {
        RawConnectionEvent {
            direction,
            protocol: Protocol::Tcp,
            interface: Some("eth0".to_string()),
            local_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            local_port: 54321,
            remote_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            remote_port: 443,
            application: Some("curl".to_string()),
            executable_path: Some("/usr/bin/curl".to_string()),
        }
    }

    #[test]
    fn test_outbound_normalizes_local_ephemeral_port() {
        let mut ev1 = sample_event(Direction::Outbound);
        ev1.local_port = 51001;
        let mut ev2 = sample_event(Direction::Outbound);
        ev2.local_port = 51002;

        let r1 = AuditRecord::from_raw(&ev1, "eth0", None, false);
        let r2 = AuditRecord::from_raw(&ev2, "eth0", None, false);

        assert_eq!(r1.local_port, "*");
        assert_eq!(r1.remote_port, "443");
        assert_eq!(r1.flow_key(), r2.flow_key());
    }

    #[test]
    fn test_inbound_normalizes_remote_ephemeral_port() {
        let mut ev1 = sample_event(Direction::Inbound);
        ev1.local_port = 8080;
        ev1.remote_port = 40001;
        let mut ev2 = sample_event(Direction::Inbound);
        ev2.local_port = 8080;
        ev2.remote_port = 40002;

        let r1 = AuditRecord::from_raw(&ev1, "eth0", None, false);
        let r2 = AuditRecord::from_raw(&ev2, "eth0", None, false);

        assert_eq!(r1.local_port, "8080");
        assert_eq!(r1.remote_port, "*");
        assert_eq!(r1.flow_key(), r2.flow_key());
    }

    #[test]
    fn test_different_interfaces_produce_distinct_flow_keys() {
        let ev = sample_event(Direction::Outbound);
        let r1 = AuditRecord::from_raw(&ev, "eth0", None, false);
        let r2 = AuditRecord::from_raw(&ev, "tun0", None, false);
        assert_ne!(r1.flow_key(), r2.flow_key());
    }

    #[test]
    fn test_keep_ephemeral_ports_preserves_both_ports() {
        let ev = sample_event(Direction::Outbound);
        let r = AuditRecord::from_raw(&ev, "eth0", None, true);
        assert_eq!(r.local_port, "54321");
        assert_eq!(r.remote_port, "443");
    }

    #[test]
    fn test_loopback_and_unspecified_filtering() {
        assert!(is_loopback_or_unspecified(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_loopback_or_unspecified(&IpAddr::V4(Ipv4Addr::new(
            127, 0, 1, 1
        ))));
        assert!(is_loopback_or_unspecified(&IpAddr::V4(
            Ipv4Addr::UNSPECIFIED
        )));
        assert!(is_loopback_or_unspecified(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_loopback_or_unspecified(&IpAddr::V6(
            Ipv6Addr::UNSPECIFIED
        )));
        let mapped: Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(is_loopback_or_unspecified(&IpAddr::V6(mapped)));

        assert!(!is_loopback_or_unspecified(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 10
        ))));
        assert!(!is_loopback_or_unspecified(&IpAddr::V6(
            "2606:4700:4700::1111".parse().unwrap()
        )));
    }
}
