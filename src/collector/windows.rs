use crate::iface::InterfaceMap;
use crate::model::{Direction, Protocol, RawConnectionEvent};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex, OnceLock};
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, MAX_PATH};
use windows::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW,
    CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
    TRACE_LEVEL_INFORMATION,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

// Microsoft-Windows-Kernel-Network {7dd42a49-5329-4832-8dfd-43d979153a88}
const KERNEL_NETWORK_GUID: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);

struct EtwState {
    tx: Sender<RawConnectionEvent>,
    iface_map: InterfaceMap,
    pid_cache: HashMap<u32, (String, String)>,
}

static ETW_STATE: OnceLock<Mutex<Option<EtwState>>> = OnceLock::new();

pub fn start_collector(tx: Sender<RawConnectionEvent>, stop: Arc<AtomicBool>) -> Result<()> {
    let state_lock = ETW_STATE.get_or_init(|| Mutex::new(None));
    {
        let mut guard = state_lock.lock().unwrap();
        *guard = Some(EtwState {
            tx,
            iface_map: InterfaceMap::new(),
            pid_cache: HashMap::new(),
        });
    }

    let session_name: Vec<u16> = "FirewallAuditKernelNet\0".encode_utf16().collect();
    let prop_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (session_name.len() * 2);
    let mut prop_buf = vec![0u8; prop_size];
    let props = unsafe { &mut *(prop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
    props.Wnode.BufferSize = prop_size as u32;
    props.Wnode.Flags = 0x00020000; // WNODE_FLAG_TRACED_GUID
    props.Wnode.ClientContext = 1;
    props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

    let mut session_handle = CONTROLTRACE_HANDLE::default();
    let status = unsafe {
        StartTraceW(
            &mut session_handle,
            PCWSTR(session_name.as_ptr()),
            props,
        )
    };
    if status != ERROR_SUCCESS {
        // Attempt to stop any stale session with the same name and retry once.
        let _ = unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE::default(),
                PCWSTR(session_name.as_ptr()),
                props,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        let retry = unsafe {
            StartTraceW(
                &mut session_handle,
                PCWSTR(session_name.as_ptr()),
                props,
            )
        };
        if retry != ERROR_SUCCESS {
            bail!("StartTraceW failed (Administrator privileges required): {:?}", retry);
        }
    }

    let enable_params = ENABLE_TRACE_PARAMETERS {
        Version: 2,
        ..Default::default()
    };
    let enable_status = unsafe {
        EnableTraceEx2(
            session_handle,
            &KERNEL_NETWORK_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_INFORMATION as u8,
            u64::MAX,
            0,
            0,
            Some(&enable_params),
        )
    };
    if enable_status != ERROR_SUCCESS {
        let _ = unsafe {
            ControlTraceW(
                session_handle,
                PCWSTR::null(),
                props,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        bail!("EnableTraceEx2 failed: {:?}", enable_status);
    }

    let mut logger_name = session_name.clone();
    let mut logfile = EVENT_TRACE_LOGFILEW::default();
    logfile.LoggerName = PWSTR(logger_name.as_mut_ptr());
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);

    let trace_handle = unsafe { OpenTraceW(&mut logfile) };
    if trace_handle.Value == u64::MAX {
        let _ = unsafe {
            ControlTraceW(
                session_handle,
                PCWSTR::null(),
                props,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        bail!("OpenTraceW failed");
    }

    // Spawn a watcher thread to stop the ETW session when `stop` becomes true.
    let stop_session_name = session_name.clone();
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        let mut stop_buf = vec![0u8; prop_size];
        let stop_props = unsafe { &mut *(stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) };
        stop_props.Wnode.BufferSize = prop_size as u32;
        stop_props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        let _ = unsafe {
            ControlTraceW(
                session_handle,
                PCWSTR(stop_session_name.as_ptr()),
                stop_props,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
    });

    let handles = [trace_handle];
    let _ = unsafe { ProcessTrace(&handles, None, None) };
    let _ = unsafe { CloseTrace(trace_handle) };
    Ok(())
}

unsafe extern "system" fn event_record_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let rec = &*record;
    if rec.EventHeader.ProviderId != KERNEL_NETWORK_GUID {
        return;
    }

    let event_id = rec.EventHeader.EventDescriptor.Id;
    let payload = if rec.UserData.is_null() || rec.UserDataLength == 0 {
        return;
    } else {
        std::slice::from_raw_parts(rec.UserData as *const u8, rec.UserDataLength as usize)
    };

    // Microsoft-Windows-Kernel-Network event IDs:
    // 12: TCPv4 Connect (outbound), 15: TCPv4 Accept (inbound)
    // 28: TCPv6 Connect (outbound), 31: TCPv6 Accept (inbound)
    // 42: UDPv4 Send (outbound), 43: UDPv4 Recv (inbound)
    // 58: UDPv6 Send (outbound), 59: UDPv6 Recv (inbound)
    let parsed = match event_id {
        12 => parse_v4_event(payload, Protocol::Tcp, Direction::Outbound),
        15 => parse_v4_event(payload, Protocol::Tcp, Direction::Inbound),
        28 => parse_v6_event(payload, Protocol::Tcp, Direction::Outbound),
        31 => parse_v6_event(payload, Protocol::Tcp, Direction::Inbound),
        42 => parse_v4_event(payload, Protocol::Udp, Direction::Outbound),
        43 => parse_v4_event(payload, Protocol::Udp, Direction::Inbound),
        58 => parse_v6_event(payload, Protocol::Udp, Direction::Outbound),
        59 => parse_v6_event(payload, Protocol::Udp, Direction::Inbound),
        _ => None,
    };

    let Some((direction, protocol, local_ip, local_port, remote_ip, remote_port, pid)) = parsed
    else {
        return;
    };

    let pid = if pid != 0 { pid } else { rec.EventHeader.ProcessId };
    let Some(lock) = ETW_STATE.get() else {
        return;
    };
    let Ok(mut guard) = lock.lock() else {
        return;
    };
    let Some(state) = guard.as_mut() else {
        return;
    };

    let iface = state.iface_map.lookup(&local_ip);
    let (app, exe_path) = state
        .pid_cache
        .entry(pid)
        .or_insert_with(|| resolve_pid_windows(pid))
        .clone();

    let _ = state.tx.send(RawConnectionEvent {
        direction,
        protocol,
        interface: Some(iface),
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        application: Some(app),
        executable_path: Some(exe_path),
    });
}

fn parse_v4_event(
    payload: &[u8],
    protocol: Protocol,
    direction: Direction,
) -> Option<(Direction, Protocol, IpAddr, u16, IpAddr, u16, u32)> {
    // Kernel-Network v4 layout: PID(4), size(4), daddr(4), saddr(4), dport(2), sport(2)
    if payload.len() < 20 {
        return None;
    }
    let pid = u32::from_ne_bytes(payload[0..4].try_into().ok()?);
    let daddr = IpAddr::V4(Ipv4Addr::new(payload[8], payload[9], payload[10], payload[11]));
    let saddr = IpAddr::V4(Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]));
    let dport = u16::from_be_bytes([payload[16], payload[17]]);
    let sport = u16::from_be_bytes([payload[18], payload[19]]);

    let (local_ip, local_port, remote_ip, remote_port) = match direction {
        Direction::Outbound => (saddr, sport, daddr, dport),
        Direction::Inbound => (daddr, dport, saddr, sport),
    };
    Some((direction, protocol, local_ip, local_port, remote_ip, remote_port, pid))
}

fn parse_v6_event(
    payload: &[u8],
    protocol: Protocol,
    direction: Direction,
) -> Option<(Direction, Protocol, IpAddr, u16, IpAddr, u16, u32)> {
    // Kernel-Network v6 layout: PID(4), size(4), daddr(16), saddr(16), dport(2), sport(2)
    if payload.len() < 44 {
        return None;
    }
    let pid = u32::from_ne_bytes(payload[0..4].try_into().ok()?);
    let daddr_bytes: [u8; 16] = payload[8..24].try_into().ok()?;
    let saddr_bytes: [u8; 16] = payload[24..40].try_into().ok()?;
    let daddr = IpAddr::V6(Ipv6Addr::from(daddr_bytes));
    let saddr = IpAddr::V6(Ipv6Addr::from(saddr_bytes));
    let dport = u16::from_be_bytes([payload[40], payload[41]]);
    let sport = u16::from_be_bytes([payload[42], payload[43]]);

    let (local_ip, local_port, remote_ip, remote_port) = match direction {
        Direction::Outbound => (saddr, sport, daddr, dport),
        Direction::Inbound => (daddr, dport, saddr, sport),
    };
    Some((direction, protocol, local_ip, local_port, remote_ip, remote_port, pid))
}

fn resolve_pid_windows(pid: u32) -> (String, String) {
    if pid == 0 || pid == 4 {
        return ("System".to_string(), "System".to_string());
    }
    unsafe {
        let Ok(handle): Result<HANDLE, _> =
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
        else {
            return ("unknown".to_string(), "unknown".to_string());
        };
        let mut buf = [0u16; MAX_PATH as usize * 2];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        )
        .is_ok();
        let _ = CloseHandle(handle);
        if ok && size > 0 {
            let exe = String::from_utf16_lossy(&buf[..size as usize]);
            let app = std::path::Path::new(&exe)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            (app, exe)
        } else {
            ("unknown".to_string(), "unknown".to_string())
        }
    }
}
