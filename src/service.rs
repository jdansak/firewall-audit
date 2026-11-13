use anyhow::Result;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ServiceConfig<'a> {
    pub output: &'a Path,
    pub dns: bool,
    pub include_loopback: bool,
    pub keep_ephemeral_ports: bool,
}

#[cfg(target_os = "linux")]
pub fn install(cfg: &ServiceConfig<'_>) -> Result<()> {
    use anyhow::{bail, Context};
    use std::process::Command;

    if unsafe { libc::geteuid() } != 0 {
        bail!("installing systemd service requires root privileges (run with sudo)");
    }

    let exe = std::env::current_exe().context("resolving current executable path")?;
    let output_abs = std::fs::canonicalize(cfg.output.parent().unwrap_or_else(|| Path::new(".")))
        .unwrap_or_else(|_| {
            cfg.output
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf()
        })
        .join(
            cfg.output
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("firewall_audit.csv")),
        );

    let mut args = vec![
        "run".to_string(),
        "--output".to_string(),
        output_abs.display().to_string(),
    ];
    if cfg.dns {
        args.push("--dns".to_string());
    }
    if cfg.include_loopback {
        args.push("--include-loopback".to_string());
    }
    if cfg.keep_ephemeral_ports {
        args.push("--keep-ephemeral-ports".to_string());
    }

    let unit = format!(
        "[Unit]\n\
         Description=Firewall Audit Kernel Event Collector\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=simple\n\
         ExecStart={} {}\n\
         Restart=on-failure\n\
         RestartSec=5\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        exe.display(),
        args.join(" ")
    );

    let unit_path = Path::new("/etc/systemd/system/firewall-audit.service");
    std::fs::write(unit_path, unit)
        .with_context(|| format!("writing systemd unit to {}", unit_path.display()))?;

    run_checked(Command::new("systemctl").args(["daemon-reload"]))?;
    run_checked(Command::new("systemctl").args(["enable", "--now", "firewall-audit.service"]))?;
    println!("Installed and started systemd service: firewall-audit.service");
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn uninstall() -> Result<()> {
    use anyhow::bail;
    use std::process::Command;

    if unsafe { libc::geteuid() } != 0 {
        bail!("uninstalling systemd service requires root privileges (run with sudo)");
    }

    let _ = Command::new("systemctl")
        .args(["disable", "--now", "firewall-audit.service"])
        .status();
    let unit_path = Path::new("/etc/systemd/system/firewall-audit.service");
    if unit_path.exists() {
        std::fs::remove_file(unit_path)?;
    }
    let _ = Command::new("systemctl").args(["daemon-reload"]).status();
    println!("Uninstalled systemd service: firewall-audit.service");
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn install(cfg: &ServiceConfig<'_>) -> Result<()> {
    use anyhow::{bail, Context};
    use std::process::Command;

    if unsafe { libc::geteuid() } != 0 {
        bail!("installing LaunchDaemon requires root privileges (run with sudo)");
    }

    let exe = std::env::current_exe().context("resolving current executable path")?;
    let mut args_xml = format!(
        "        <string>{}</string>\n        <string>run</string>\n        <string>--output</string>\n        <string>{}</string>\n",
        exe.display(),
        cfg.output.display()
    );
    if cfg.dns {
        args_xml.push_str("        <string>--dns</string>\n");
    }
    if cfg.include_loopback {
        args_xml.push_str("        <string>--include-loopback</string>\n");
    }
    if cfg.keep_ephemeral_ports {
        args_xml.push_str("        <string>--keep-ephemeral-ports</string>\n");
    }

    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
             <key>Label</key>\n\
             <string>com.firewall-audit.daemon</string>\n\
             <key>ProgramArguments</key>\n\
             <array>\n\
         {args_xml}\
             </array>\n\
             <key>RunAtLoad</key>\n\
             <true/>\n\
             <key>KeepAlive</key>\n\
             <true/>\n\
             <key>StandardOutPath</key>\n\
             <string>/var/log/firewall-audit.log</string>\n\
             <key>StandardErrorPath</key>\n\
             <string>/var/log/firewall-audit.err.log</string>\n\
         </dict>\n\
         </plist>\n"
    );

    let plist_path = Path::new("/Library/LaunchDaemons/com.firewall-audit.daemon.plist");
    std::fs::write(plist_path, plist)
        .with_context(|| format!("writing LaunchDaemon plist to {}", plist_path.display()))?;

    run_checked(Command::new("launchctl").args(["load", "-w", &plist_path.to_string_lossy()]))?;
    println!("Installed and loaded LaunchDaemon: com.firewall-audit.daemon");
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn uninstall() -> Result<()> {
    use anyhow::bail;
    use std::process::Command;

    if unsafe { libc::geteuid() } != 0 {
        bail!("uninstalling LaunchDaemon requires root privileges (run with sudo)");
    }

    let plist_path = Path::new("/Library/LaunchDaemons/com.firewall-audit.daemon.plist");
    if plist_path.exists() {
        let _ = Command::new("launchctl")
            .args(["unload", "-w", &plist_path.to_string_lossy()])
            .status();
        std::fs::remove_file(plist_path)?;
    }
    println!("Uninstalled LaunchDaemon: com.firewall-audit.daemon");
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn install(cfg: &ServiceConfig<'_>) -> Result<()> {
    use anyhow::Context;
    use std::process::Command;

    let exe = std::env::current_exe().context("resolving current executable path")?;
    let mut bin_path = format!(
        "\"{}\" --service run --output \"{}\"",
        exe.display(),
        cfg.output.display()
    );
    if cfg.dns {
        bin_path.push_str(" --dns");
    }
    if cfg.include_loopback {
        bin_path.push_str(" --include-loopback");
    }
    if cfg.keep_ephemeral_ports {
        bin_path.push_str(" --keep-ephemeral-ports");
    }

    run_checked(Command::new("sc.exe").args([
        "create",
        "FirewallAudit",
        "binPath=",
        &bin_path,
        "start=",
        "auto",
        "DisplayName=",
        "Firewall Audit Service",
    ]))?;
    run_checked(Command::new("sc.exe").args(["start", "FirewallAudit"]))?;
    println!("Installed and started Windows Service: FirewallAudit");
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn uninstall() -> Result<()> {
    use std::process::Command;

    let _ = Command::new("sc.exe")
        .args(["stop", "FirewallAudit"])
        .status();
    run_checked(Command::new("sc.exe").args(["delete", "FirewallAudit"]))?;
    println!("Uninstalled Windows Service: FirewallAudit");
    Ok(())
}

fn run_checked(cmd: &mut std::process::Command) -> Result<()> {
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("command {:?} failed with status {}", cmd, status);
    }
    Ok(())
}
