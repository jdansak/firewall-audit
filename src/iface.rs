use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Maps local IP addresses to network interface names for multi-homed systems.
pub struct InterfaceMap {
    ip_to_iface: HashMap<IpAddr, String>,
    last_refresh: Instant,
    refresh_interval: Duration,
}

impl InterfaceMap {
    pub fn new() -> Self {
        let mut map = Self {
            ip_to_iface: HashMap::new(),
            last_refresh: Instant::now() - Duration::from_secs(60),
            refresh_interval: Duration::from_secs(30),
        };
        map.refresh();
        map
    }

    pub fn refresh(&mut self) {
        self.ip_to_iface = enumerate_interface_ips();
        self.last_refresh = Instant::now();
    }

    fn maybe_refresh(&mut self) {
        if self.last_refresh.elapsed() >= self.refresh_interval {
            self.refresh();
        }
    }

    #[allow(dead_code)]
    pub fn is_local_ip(&mut self, ip: &IpAddr) -> bool {
        self.maybe_refresh();
        self.ip_to_iface.contains_key(ip)
    }

    pub fn lookup(&mut self, local_ip: &IpAddr) -> String {
        self.maybe_refresh();
        if let Some(iface) = self.ip_to_iface.get(local_ip) {
            return iface.clone();
        }
        // Refresh once on miss in case an interface/VPN came up recently.
        self.refresh();
        if let Some(iface) = self.ip_to_iface.get(local_ip) {
            return iface.clone();
        }
        if local_ip.is_unspecified() {
            "*".to_string()
        } else {
            "unknown".to_string()
        }
    }
}

#[cfg(unix)]
fn enumerate_interface_ips() -> HashMap<IpAddr, String> {
    use std::ffi::CStr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut result = HashMap::new();
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();

    // SAFETY: getifaddrs allocates a linked list freed by freeifaddrs below.
    if unsafe { libc::getifaddrs(&mut ifaddrs) } != 0 {
        return result;
    }

    let mut cur = ifaddrs;
    while !cur.is_null() {
        // SAFETY: cur is non-null and points to a valid ifaddrs node.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_name.is_null() && !ifa.ifa_addr.is_null() {
            // SAFETY: ifa_name is a valid NUL-terminated C string.
            let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: ifa_addr points to a sockaddr with valid sa_family.
            let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;
            match family {
                libc::AF_INET => {
                    // SAFETY: family is AF_INET so ifa_addr is sockaddr_in.
                    let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                    let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
                    result.insert(ip, name);
                }
                libc::AF_INET6 => {
                    // SAFETY: family is AF_INET6 so ifa_addr is sockaddr_in6.
                    let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                    let ip = IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr));
                    result.insert(ip, name);
                }
                _ => {}
            }
        }
        cur = ifa.ifa_next;
    }

    // SAFETY: ifaddrs was allocated by getifaddrs.
    unsafe { libc::freeifaddrs(ifaddrs) };
    result
}

#[cfg(windows)]
fn enumerate_interface_ips() -> HashMap<IpAddr, String> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    let mut result = HashMap::new();
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    let mut buf = vec![0u8; size as usize];

    let mut ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            flags,
            None,
            Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut size,
        )
    };

    if ret == ERROR_BUFFER_OVERFLOW.0 {
        buf.resize(size as usize, 0);
        ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
    }

    if ret != 0 {
        return result;
    }

    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cur.is_null() {
        let adapter = unsafe { &*cur };
        let friendly_name = unsafe {
            if !adapter.FriendlyName.0.is_null() {
                adapter.FriendlyName.to_string().unwrap_or_default()
            } else {
                String::new()
            }
        };

        let mut unicast = adapter.FirstUnicastAddress;
        while !unicast.is_null() {
            let ua = unsafe { &*unicast };
            let sockaddr = ua.Address.lpSockaddr;
            if !sockaddr.is_null() && !friendly_name.is_empty() {
                let family = unsafe { (*sockaddr).sa_family };
                if family == AF_INET {
                    let sin = unsafe { &*(sockaddr as *const SOCKADDR_IN) };
                    let bytes = unsafe { sin.sin_addr.S_un.S_addr }.to_ne_bytes();
                    result.insert(IpAddr::V4(Ipv4Addr::from(bytes)), friendly_name.clone());
                } else if family == AF_INET6 {
                    let sin6 = unsafe { &*(sockaddr as *const SOCKADDR_IN6) };
                    let bytes = unsafe { sin6.sin6_addr.u.Byte };
                    result.insert(IpAddr::V6(Ipv6Addr::from(bytes)), friendly_name.clone());
                }
            }
            unicast = ua.Next;
        }
        cur = adapter.Next;
    }

    result
}
