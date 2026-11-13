use crate::iface::InterfaceMap;
use crate::model::{Direction, Protocol, RawConnectionEvent};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

pub fn start_collector(tx: Sender<RawConnectionEvent>, stop: Arc<AtomicBool>) -> Result<()> {
    let mut child = Command::new("nettop")
        .args(["-P", "-L", "0", "-n", "-x", "-J", "interface,state"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning macOS nettop kernel NStat stream")?;

    let stdout = child
        .stdout
        .take()
        .context("capturing nettop stdout")?;
    let reader = BufReader::new(stdout);
    let mut iface_map = InterfaceMap::new();
    let mut pid_cache: HashMap<u32, (String, String)> = HashMap::new();
    let mut current_proc: Option<(String, u32)> = None;

    for line in reader.lines() {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let Ok(line) = line else {
            break;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("time,") {
            continue;
        }

        // nettop CSV lines:
        // Process summary row: ",curl.12345,en0,,"
        // Socket row: ",tcp4 10.0.0.5:51234<->93.184.216.34:443,en0,Established,"
        let cols: Vec<&str> = trimmed.split(',').collect();
        if cols.len() < 2 {
            continue;
        }
        let entry = cols[1].trim();
        let iface_col = cols.get(2).map(|s| s.trim()).unwrap_or("");

        if let Some((proto, local, remote)) = parse_nettop_socket(entry) {
            let state = cols.get(3).map(|s| s.trim()).unwrap_or("");
            let direction = if state.eq_ignore_ascii_case("Listen")
                || (local.1 < 32768 && remote.1 >= 32768)
            {
                Direction::Inbound
            } else {
                Direction::Outbound
            };

            let iface = if !iface_col.is_empty() {
                iface_col.to_string()
            } else {
                iface_map.lookup(&local.0)
            };

            let (app, exe_path) = match &current_proc {
                Some((name, pid)) => {
                    let (cached_app, cached_exe) = pid_cache
                        .entry(*pid)
                        .or_insert_with(|| resolve_pid_macos(*pid, name))
                        .clone();
                    (Some(cached_app), Some(cached_exe))
                }
                None => (None, None),
            };

            if tx
                .send(RawConnectionEvent {
                    direction,
                    protocol: proto,
                    interface: Some(iface),
                    local_ip: local.0,
                    local_port: local.1,
                    remote_ip: remote.0,
                    remote_port: remote.1,
                    application: app,
                    executable_path: exe_path,
                })
                .is_err()
            {
                break;
            }
        } else if let Some((name, pid)) = parse_process_header(entry) {
            current_proc = Some((name, pid));
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

fn parse_process_header(entry: &str) -> Option<(String, u32)> {
    let (name, pid_str) = entry.rsplit_once('.')?;
    let pid = pid_str.parse::<u32>().ok()?;
    Some((name.to_string(), pid))
}

type NettopSocket = (Protocol, (IpAddr, u16), (IpAddr, u16));

fn parse_nettop_socket(entry: &str) -> Option<NettopSocket> {
    let (proto_str, endpoints) = entry.split_once(' ')?;
    let proto = if proto_str.starts_with("tcp") {
        Protocol::Tcp
    } else if proto_str.starts_with("udp") {
        Protocol::Udp
    } else {
        return None;
    };
    let (lhs, rhs) = endpoints.split_once("<->")?;
    let local = parse_ip_port(lhs)?;
    let remote = parse_ip_port(rhs)?;
    if remote.0.is_unspecified() && remote.1 == 0 {
        return None;
    }
    Some((proto, local, remote))
}

fn parse_ip_port(s: &str) -> Option<(IpAddr, u16)> {
    let (ip_str, port_str) = s.rsplit_once(':')?;
    let ip_clean = ip_str.trim_start_matches('[').trim_end_matches(']');
    // Strip IPv6 scope IDs like %en0
    let ip_no_scope = ip_clean.split('%').next().unwrap_or(ip_clean);
    let ip: IpAddr = ip_no_scope.parse().ok()?;
    let port: u16 = port_str.parse().ok()?;
    Some((ip, port))
}

extern "C" {
    fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_void, buffersize: u32) -> libc::c_int;
}

fn resolve_pid_macos(pid: u32, fallback_name: &str) -> (String, String) {
    let mut buf = vec![0u8; 4096];
    let ret = unsafe {
        proc_pidpath(
            pid as libc::c_int,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as u32,
        )
    };
    if ret > 0 {
        let exe = String::from_utf8_lossy(&buf[..ret as usize]).into_owned();
        let app = std::path::Path::new(&exe)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(fallback_name)
            .to_string();
        (app, exe)
    } else {
        (fallback_name.to_string(), fallback_name.to_string())
    }
}
