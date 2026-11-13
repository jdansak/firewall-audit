use crate::iface::InterfaceMap;
use crate::model::{Direction, Protocol, RawConnectionEvent};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{Duration, Instant};

const NETLINK_NETFILTER: i32 = 12;
const NFNLGRP_CONNTRACK_NEW: u32 = 1;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_NEW: u16 = 0;

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;

const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;

const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | (1 << 14));

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConntrackTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    comm: String,
    exe_path: String,
}

struct InodeCache {
    inode_to_proc: HashMap<u64, ProcessInfo>,
    last_refresh: Instant,
}

impl InodeCache {
    fn new() -> Self {
        Self {
            inode_to_proc: HashMap::new(),
            last_refresh: Instant::now() - Duration::from_secs(60),
        }
    }

    fn refresh(&mut self) {
        let mut map = HashMap::new();
        let Ok(entries) = fs::read_dir("/proc") else {
            return;
        };
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let Some(pid_str) = fname.to_str() else {
                continue;
            };
            let Ok(_pid) = pid_str.parse::<u32>() else {
                continue;
            };
            let fd_dir = entry.path().join("fd");
            let Ok(fds) = fs::read_dir(&fd_dir) else {
                continue;
            };

            let mut proc_info: Option<ProcessInfo> = None;
            for fd in fds.flatten() {
                let Ok(target) = fs::read_link(fd.path()) else {
                    continue;
                };
                let Some(target_str) = target.to_str() else {
                    continue;
                };
                if let Some(inode_str) = target_str
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                {
                    if let Ok(inode) = inode_str.parse::<u64>() {
                        let info = proc_info.get_or_insert_with(|| {
                            let comm = fs::read_to_string(entry.path().join("comm"))
                                .map(|s| s.trim().to_string())
                                .unwrap_or_else(|_| "unknown".to_string());
                            let exe_path = fs::read_link(entry.path().join("exe"))
                                .map(|p| p.to_string_lossy().into_owned())
                                .unwrap_or_else(|_| comm.clone());
                            ProcessInfo {
                                            comm,
                                exe_path,
                            }
                        });
                        map.insert(inode, info.clone());
                    }
                }
            }
        }
        self.inode_to_proc = map;
        self.last_refresh = Instant::now();
    }

    fn lookup_socket_process(
        &mut self,
        proto: Protocol,
        local_ip: IpAddr,
        local_port: u16,
        remote_ip: IpAddr,
        remote_port: u16,
    ) -> Option<ProcessInfo> {
        let inode = find_proc_net_inode(proto, local_ip, local_port, remote_ip, remote_port)?;
        if let Some(info) = self.inode_to_proc.get(&inode) {
            return Some(info.clone());
        }
        if self.last_refresh.elapsed() >= Duration::from_millis(250) {
            self.refresh();
            return self.inode_to_proc.get(&inode).cloned();
        }
        None
    }
}

fn find_proc_net_inode(
    proto: Protocol,
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
) -> Option<u64> {
    let path = match (proto, local_ip) {
        (Protocol::Tcp, IpAddr::V4(_)) => "/proc/net/tcp",
        (Protocol::Tcp, IpAddr::V6(_)) => "/proc/net/tcp6",
        (Protocol::Udp, IpAddr::V4(_)) => "/proc/net/udp",
        (Protocol::Udp, IpAddr::V6(_)) => "/proc/net/udp6",
        _ => return None,
    };

    let content = fs::read_to_string(path).ok()?;
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let Some((l_ip, l_port)) = parse_proc_addr(cols[1]) else {
            continue;
        };
        let Some((r_ip, r_port)) = parse_proc_addr(cols[2]) else {
            continue;
        };
        if l_port == local_port
            && l_ip == local_ip
            && ((r_port == remote_port && r_ip == remote_ip) || (r_port == 0 && r_ip.is_unspecified()))
        {
            if let Ok(inode) = cols[9].parse::<u64>() {
                if inode > 0 {
                    return Some(inode);
                }
            }
        }
    }
    None
}

fn parse_proc_addr(s: &str) -> Option<(IpAddr, u16)> {
    let (ip_hex, port_hex) = s.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if ip_hex.len() == 8 {
        let raw = u32::from_str_radix(ip_hex, 16).ok()?;
        let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(raw.swap_bytes())));
        Some((ip, port))
    } else if ip_hex.len() == 32 {
        let mut bytes = [0u8; 16];
        for (i, chunk) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            let word = u32::from_str_radix(&ip_hex[i * 8..(i + 1) * 8], 16).ok()?;
            chunk.copy_from_slice(&word.to_ne_bytes());
        }
        Some((IpAddr::V6(Ipv6Addr::from(bytes)), port))
    } else {
        None
    }
}

struct OwnedSocket(RawFd);
impl Drop for OwnedSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

pub fn start_collector(tx: Sender<RawConnectionEvent>, stop: Arc<AtomicBool>) -> Result<()> {
    match open_conntrack_socket() {
        Ok(sock) => run_conntrack_loop(sock, tx, stop),
        Err(e) => {
            eprintln!(
                "warning: NETLINK_NETFILTER conntrack stream unavailable ({e}); falling back to /proc/net polling"
            );
            run_proc_fallback_loop(tx, stop)
        }
    }
}

fn open_conntrack_socket() -> Result<OwnedSocket> {
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_NETFILTER,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("creating NETLINK_NETFILTER socket");
    }
    let sock = OwnedSocket(fd);

    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 500_000,
    };
    unsafe {
        libc::setsockopt(
            sock.0,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_pid = 0;
    addr.nl_groups = NFNLGRP_CONNTRACK_NEW;

    let rc = unsafe {
        libc::bind(
            sock.0,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("binding NFNLGRP_CONNTRACK_NEW");
    }

    Ok(sock)
}

fn run_conntrack_loop(
    sock: OwnedSocket,
    tx: Sender<RawConnectionEvent>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut iface_map = InterfaceMap::new();
    let mut inode_cache = InodeCache::new();

    while !stop.load(Ordering::Relaxed) {
        let n = unsafe {
            libc::recv(
                sock.0,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.kind() == std::io::ErrorKind::TimedOut
                || err.kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            return Err(err).context("reading NETLINK_NETFILTER event");
        }
        let data = &buf[..n as usize];
        for tuple in parse_netlink_conntrack_messages(data) {
            let proto = Protocol::from_ip_proto(tuple.proto);
            let (direction, local_ip, local_port, remote_ip, remote_port) =
                if iface_map.is_local_ip(&tuple.src_ip) {
                    (
                        Direction::Outbound,
                        tuple.src_ip,
                        tuple.src_port,
                        tuple.dst_ip,
                        tuple.dst_port,
                    )
                } else if iface_map.is_local_ip(&tuple.dst_ip) {
                    (
                        Direction::Inbound,
                        tuple.dst_ip,
                        tuple.dst_port,
                        tuple.src_ip,
                        tuple.src_port,
                    )
                } else {
                    continue;
                };

            let iface = iface_map.lookup(&local_ip);
            let proc_info = inode_cache.lookup_socket_process(
                proto,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
            );

            let ev = RawConnectionEvent {
                direction,
                protocol: proto,
                interface: Some(iface),
                local_ip,
                local_port,
                remote_ip,
                remote_port,
                application: proc_info.as_ref().map(|p| p.comm.clone()),
                executable_path: proc_info.map(|p| p.exe_path),
            };
            if tx.send(ev).is_err() {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn run_proc_fallback_loop(tx: Sender<RawConnectionEvent>, stop: Arc<AtomicBool>) -> Result<()> {
    let mut iface_map = InterfaceMap::new();
    let mut inode_cache = InodeCache::new();
    let mut seen_inodes = std::collections::HashSet::new();

    while !stop.load(Ordering::Relaxed) {
        inode_cache.refresh();
        for (path, proto) in [
            ("/proc/net/tcp", Protocol::Tcp),
            ("/proc/net/tcp6", Protocol::Tcp),
            ("/proc/net/udp", Protocol::Udp),
            ("/proc/net/udp6", Protocol::Udp),
        ] {
            let Ok(content) = fs::read_to_string(path) else {
                continue;
            };
            for line in content.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() < 10 {
                    continue;
                }
                let Ok(inode) = cols[9].parse::<u64>() else {
                    continue;
                };
                if inode == 0 || !seen_inodes.insert(inode) {
                    continue;
                }
                let Some((local_ip, local_port)) = parse_proc_addr(cols[1]) else {
                    continue;
                };
                let Some((remote_ip, remote_port)) = parse_proc_addr(cols[2]) else {
                    continue;
                };
                if remote_ip.is_unspecified() && remote_port == 0 {
                    continue;
                }
                // Heuristic for fallback polling: state 01 = ESTABLISHED; if local_port < 32768 and remote_port >= 32768 treat as inbound.
                let direction = if local_port < 32768 && remote_port >= 32768 {
                    Direction::Inbound
                } else {
                    Direction::Outbound
                };
                let iface = iface_map.lookup(&local_ip);
                let proc_info = inode_cache.inode_to_proc.get(&inode);
                let ev = RawConnectionEvent {
                    direction,
                    protocol: proto,
                    interface: Some(iface),
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    application: proc_info.map(|p| p.comm.clone()),
                    executable_path: proc_info.map(|p| p.exe_path.clone()),
                };
                if tx.send(ev).is_err() {
                    return Ok(());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(())
}

/// Parses one or more Netlink `nlmsghdr` + `nfgenmsg` + `nlattr` conntrack NEW messages.
pub fn parse_netlink_conntrack_messages(mut data: &[u8]) -> Vec<ConntrackTuple> {
    let mut out = Vec::new();
    while data.len() >= 16 {
        let nlmsg_len = u32::from_ne_bytes(data[0..4].try_into().unwrap()) as usize;
        let nlmsg_type = u16::from_ne_bytes(data[4..6].try_into().unwrap());
        if nlmsg_len < 16 || nlmsg_len > data.len() {
            break;
        }
        let expected_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;
        if nlmsg_type == expected_type && nlmsg_len >= 20 {
            // 16 bytes nlmsghdr + 4 bytes nfgenmsg
            let attrs = &data[20..nlmsg_len];
            if let Some(tuple) = parse_ct_attrs(attrs) {
                out.push(tuple);
            }
        }
        let aligned = (nlmsg_len + 3) & !3;
        if aligned >= data.len() {
            break;
        }
        data = &data[aligned..];
    }
    out
}

fn parse_ct_attrs(attrs: &[u8]) -> Option<ConntrackTuple> {
    for (attr_type, payload) in iter_nlattrs(attrs) {
        if (attr_type & NLA_TYPE_MASK) == CTA_TUPLE_ORIG {
            return parse_tuple(payload);
        }
    }
    None
}

fn parse_tuple(attrs: &[u8]) -> Option<ConntrackTuple> {
    let mut src_ip = None;
    let mut dst_ip = None;
    let mut proto = None;
    let mut src_port = 0u16;
    let mut dst_port = 0u16;

    for (attr_type, payload) in iter_nlattrs(attrs) {
        match attr_type & NLA_TYPE_MASK {
            CTA_TUPLE_IP => {
                for (ip_type, ip_val) in iter_nlattrs(payload) {
                    match ip_type & NLA_TYPE_MASK {
                        CTA_IP_V4_SRC if ip_val.len() == 4 => {
                            let octets: [u8; 4] = ip_val.try_into().ok()?;
                            src_ip = Some(IpAddr::V4(Ipv4Addr::from(octets)));
                        }
                        CTA_IP_V4_DST if ip_val.len() == 4 => {
                            let octets: [u8; 4] = ip_val.try_into().ok()?;
                            dst_ip = Some(IpAddr::V4(Ipv4Addr::from(octets)));
                        }
                        CTA_IP_V6_SRC if ip_val.len() == 16 => {
                            let octets: [u8; 16] = ip_val.try_into().ok()?;
                            src_ip = Some(IpAddr::V6(Ipv6Addr::from(octets)));
                        }
                        CTA_IP_V6_DST if ip_val.len() == 16 => {
                            let octets: [u8; 16] = ip_val.try_into().ok()?;
                            dst_ip = Some(IpAddr::V6(Ipv6Addr::from(octets)));
                        }
                        _ => {}
                    }
                }
            }
            CTA_TUPLE_PROTO => {
                for (p_type, p_val) in iter_nlattrs(payload) {
                    match p_type & NLA_TYPE_MASK {
                        CTA_PROTO_NUM if !p_val.is_empty() => {
                            proto = Some(p_val[0]);
                        }
                        CTA_PROTO_SRC_PORT if p_val.len() == 2 => {
                            src_port = u16::from_be_bytes([p_val[0], p_val[1]]);
                        }
                        CTA_PROTO_DST_PORT if p_val.len() == 2 => {
                            dst_port = u16::from_be_bytes([p_val[0], p_val[1]]);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    Some(ConntrackTuple {
        src_ip: src_ip?,
        dst_ip: dst_ip?,
        proto: proto?,
        src_port,
        dst_port,
    })
}

fn iter_nlattrs(mut data: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while data.len() >= 4 {
        let len = u16::from_ne_bytes([data[0], data[1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[2], data[3]]);
        if len < 4 || len > data.len() {
            break;
        }
        out.push((attr_type, &data[4..len]));
        let aligned = (len + 3) & !3;
        if aligned >= data.len() {
            break;
        }
        data = &data[aligned..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_nlattr(buf: &mut Vec<u8>, attr_type: u16, payload: &[u8]) {
        let len = (4 + payload.len()) as u16;
        buf.extend_from_slice(&len.to_ne_bytes());
        buf.extend_from_slice(&attr_type.to_ne_bytes());
        buf.extend_from_slice(payload);
        while !buf.len().is_multiple_of(4) {
            buf.push(0);
        }
    }

    #[test]
    fn test_parse_synthetic_netlink_conntrack_v4_tcp() {
        let mut ip_attrs = Vec::new();
        push_nlattr(&mut ip_attrs, CTA_IP_V4_SRC, &[10, 0, 1, 42]);
        push_nlattr(&mut ip_attrs, CTA_IP_V4_DST, &[1, 1, 1, 1]);

        let mut proto_attrs = Vec::new();
        push_nlattr(&mut proto_attrs, CTA_PROTO_NUM, &[6]);
        push_nlattr(&mut proto_attrs, CTA_PROTO_SRC_PORT, &54321u16.to_be_bytes());
        push_nlattr(&mut proto_attrs, CTA_PROTO_DST_PORT, &443u16.to_be_bytes());

        let mut tuple_attrs = Vec::new();
        push_nlattr(&mut tuple_attrs, CTA_TUPLE_IP | NLA_F_NESTED, &ip_attrs);
        push_nlattr(
            &mut tuple_attrs,
            CTA_TUPLE_PROTO | NLA_F_NESTED,
            &proto_attrs,
        );

        let mut ct_attrs = Vec::new();
        push_nlattr(&mut ct_attrs, CTA_TUPLE_ORIG | NLA_F_NESTED, &tuple_attrs);

        let total_len = (20 + ct_attrs.len()) as u32;
        let msg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW;

        let mut msg = Vec::new();
        msg.extend_from_slice(&total_len.to_ne_bytes());
        msg.extend_from_slice(&msg_type.to_ne_bytes());
        msg.extend_from_slice(&0u16.to_ne_bytes()); // flags
        msg.extend_from_slice(&1u32.to_ne_bytes()); // seq
        msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
        // nfgenmsg: family=AF_INET(2), version=0, res_id=0
        msg.extend_from_slice(&[2, 0, 0, 0]);
        msg.extend_from_slice(&ct_attrs);

        let parsed = parse_netlink_conntrack_messages(&msg);
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0],
            ConntrackTuple {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 42)),
                dst_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                proto: 6,
                src_port: 54321,
                dst_port: 443,
            }
        );
    }
}
