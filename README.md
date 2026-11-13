# firewall-audit

Cross-platform (Linux, macOS, Windows) kernel-event firewall audit tool written in Rust.

`firewall-audit` is designed to run over long periods to collect every unique inbound and outbound network rule—including the **network interface** (for multi-homed hosts) and **application / executable path**—so you can craft minimal, least-privilege firewall pinholes.

## Features

- **OS Kernel Event Tracing**:
  - **Linux**: `NETLINK_NETFILTER` conntrack event stream (`NFNLGRP_CONNTRACK_NEW`) with `/proc` socket-inode process attribution (and automatic `/proc/net` fallback if `nf_conntrack` is unavailable).
  - **Windows**: `Microsoft-Windows-Kernel-Network` ETW real-time trace session with `QueryFullProcessImageNameW` process attribution.
  - **macOS**: Kernel `NStat` stream (`nettop -P -L 0 -n -x`) with `proc_pidpath` executable resolution.
- **Multi-Homed Interface Tracking**: Records the exact network interface (`eth0`, `en0`, `tun0`, `Ethernet`, `Wi-Fi`, etc.) each connection is seen on.
- **Deduplicated CSV Output**: Only writes unique firewall rule tuples (and reloads existing CSV rows on startup so restarts never produce duplicates).
- **Minimal Pinhole Normalization**: By default, ephemeral ports are normalized to `*` (`local_port` for outbound, `remote_port` for inbound). Use `--keep-ephemeral-ports` to record exact ports.
- **Loopback Exclusion**: Loopback (`127.0.0.0/8`, `::1`, `::ffff:127.x.x.x`) and unspecified addresses are excluded by default (`--include-loopback` to include).
- **Optional DNS Correlation**: Raw IPs by default; pass `--dns` to enable cached background reverse DNS lookups (`dns_name`).
- **Background Service Installer**: Built-in `install` and `uninstall` commands for `systemd` (Linux), `launchd` (macOS), and Windows Services.

## CSV Schema

```csv
direction,protocol,interface,local_port,remote_ip,remote_port,application,executable_path,dns_name
```

- `direction`: `inbound` or `outbound`
- `protocol`: `tcp`, `udp`, `icmp`, or `proto-<num>`
- `interface`: interface name (e.g. `eth0`, `en0`, `Ethernet`, `tun0`)
- `local_port`: `*` for outbound (unless `--keep-ephemeral-ports`), listening port for inbound
- `remote_ip`: remote IPv4/IPv6 address
- `remote_port`: destination port for outbound, `*` for inbound (unless `--keep-ephemeral-ports`)
- `application`: process/binary name
- `executable_path`: full path to executable
- `dns_name`: reverse DNS hostname (empty unless `--dns` is passed)

## Build

```bash
cargo build --release
```

Binary will be at `target/release/firewall-audit` (or `firewall-audit.exe` on Windows).

## Usage

### Foreground Run

```bash
# Linux / macOS (root required for full kernel event & process visibility)
sudo ./target/release/firewall-audit run --output /var/log/firewall_audit.csv

# With optional reverse DNS correlation
sudo ./target/release/firewall-audit run --output firewall_audit.csv --dns
```

### Install / Uninstall as a Background Service

```bash
# Install (Linux systemd / macOS launchd / Windows Service)
sudo ./target/release/firewall-audit install --output /var/log/firewall_audit.csv

# Uninstall
sudo ./target/release/firewall-audit uninstall
```

On Windows, run from an **Administrator** PowerShell / Command Prompt:

```powershell
.\firewall-audit.exe install --output C:\ProgramData\firewall_audit.csv
.\firewall-audit.exe uninstall
```
