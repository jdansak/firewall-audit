mod collector;
mod dns;
mod iface;
mod model;
mod service;
mod store;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use dns::DnsResolver;
use iface::InterfaceMap;
use model::{is_loopback_or_unspecified, AuditRecord};
use service::ServiceConfig;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use store::CsvStore;

#[derive(Parser, Debug)]
#[command(
    name = "firewall-audit",
    version,
    about = "Cross-platform kernel-event firewall audit tool for identifying minimal firewall pinholes"
)]
struct Cli {
    /// Internal flag used by Windows Service Control Manager
    #[arg(long, hide = true)]
    service: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the audit collector in the foreground (default)
    Run(RunArgs),
    /// Install firewall-audit as an OS background service
    Install(InstallArgs),
    /// Uninstall the OS background service
    Uninstall,
}

#[derive(Args, Debug, Clone)]
struct RunArgs {
    /// Output CSV file path
    #[arg(short, long, default_value = "firewall_audit.csv")]
    output: PathBuf,

    /// Enable background reverse DNS lookup for remote_ip -> dns_name
    #[arg(long, default_value_t = false)]
    dns: bool,

    /// Include loopback (127.0.0.0/8, ::1) and unspecified (0.0.0.0, ::) addresses
    #[arg(long, default_value_t = false)]
    include_loopback: bool,

    /// Keep exact ephemeral ports instead of normalizing them to '*'
    #[arg(long, default_value_t = false)]
    keep_ephemeral_ports: bool,

    /// CSV flush interval in seconds
    #[arg(long, default_value_t = 5)]
    flush_interval: u64,
}

#[derive(Args, Debug, Clone)]
struct InstallArgs {
    /// Output CSV file path for the installed service
    #[arg(short, long, default_value = "firewall_audit.csv")]
    output: PathBuf,

    /// Enable background reverse DNS lookup in the installed service
    #[arg(long, default_value_t = false)]
    dns: bool,

    /// Include loopback addresses in the installed service
    #[arg(long, default_value_t = false)]
    include_loopback: bool,

    /// Keep exact ephemeral ports in the installed service
    #[arg(long, default_value_t = false)]
    keep_ephemeral_ports: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    #[cfg(target_os = "windows")]
    if cli.service {
        return run_as_windows_service(cli.command);
    }

    match cli.command {
        Some(Commands::Install(args)) => service::install(&ServiceConfig {
            output: &args.output,
            dns: args.dns,
            include_loopback: args.include_loopback,
            keep_ephemeral_ports: args.keep_ephemeral_ports,
        }),
        Some(Commands::Uninstall) => service::uninstall(),
        Some(Commands::Run(args)) => run_audit(args, Arc::new(AtomicBool::new(false))),
        None => run_audit(
            RunArgs {
                output: PathBuf::from("firewall_audit.csv"),
                dns: false,
                include_loopback: false,
                keep_ephemeral_ports: false,
                flush_interval: 5,
            },
            Arc::new(AtomicBool::new(false)),
        ),
    }
}

fn run_audit(args: RunArgs, stop: Arc<AtomicBool>) -> Result<()> {
    let stop_signal = Arc::clone(&stop);
    let _ = ctrlc::set_handler(move || {
        stop_signal.store(true, Ordering::SeqCst);
    });

    let mut store = CsvStore::open(&args.output)?;
    let mut dns = DnsResolver::new(args.dns);
    let mut iface_map = InterfaceMap::new();
    let flush_every = Duration::from_secs(args.flush_interval.max(1));
    let mut last_flush = Instant::now();

    let (tx, rx) = mpsc::channel();
    let collector_stop = Arc::clone(&stop);
    let collector_handle = std::thread::spawn(move || {
        if let Err(e) = collector::start_collector(tx, collector_stop) {
            eprintln!("collector error: {e:#}");
        }
    });

    println!(
        "firewall-audit running (output: {}, dns: {}, include_loopback: {}, keep_ephemeral_ports: {})",
        args.output.display(),
        args.dns,
        args.include_loopback,
        args.keep_ephemeral_ports
    );

    while !stop.load(Ordering::Relaxed) {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(ev) => {
                if !args.include_loopback
                    && (is_loopback_or_unspecified(&ev.remote_ip)
                        || is_loopback_or_unspecified(&ev.local_ip))
                {
                    continue;
                }

                let iface = ev
                    .interface
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                    .unwrap_or_else(|| iface_map.lookup(&ev.local_ip));

                let dns_name = dns.resolve(&ev.remote_ip);
                let rec = AuditRecord::from_raw(
                    &ev,
                    &iface,
                    dns_name,
                    args.keep_ephemeral_ports,
                );
                let _ = store.record_if_new(&rec)?;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if last_flush.elapsed() >= flush_every {
            store.flush()?;
            last_flush = Instant::now();
        }
    }

    store.flush()?;
    let _ = collector_handle.join();
    println!(
        "firewall-audit stopped. {} unique rule(s) recorded in {}",
        store.unique_count(),
        args.output.display()
    );
    Ok(())
}

#[cfg(target_os = "windows")]
fn run_as_windows_service(command: Option<Commands>) -> Result<()> {
    use std::ffi::OsString;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    static SERVICE_ARGS: std::sync::OnceLock<RunArgs> = std::sync::OnceLock::new();
    let run_args = match command {
        Some(Commands::Run(args)) => args,
        _ => RunArgs {
            output: PathBuf::from("firewall_audit.csv"),
            dns: false,
            include_loopback: false,
            keep_ephemeral_ports: false,
            flush_interval: 5,
        },
    };
    let _ = SERVICE_ARGS.set(run_args);

    define_windows_service!(ffi_service_main, my_service_main);

    fn my_service_main(_arguments: Vec<OsString>) {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_handler = Arc::clone(&stop);
        let Ok(status_handle) =
            service_control_handler::register("FirewallAudit", move |control_event| {
                match control_event {
                    ServiceControl::Stop | ServiceControl::Shutdown => {
                        stop_handler.store(true, Ordering::SeqCst);
                        ServiceControlHandlerResult::NoError
                    }
                    ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                    _ => ServiceControlHandlerResult::NotImplemented,
                }
            })
        else {
            return;
        };

        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });

        if let Some(args) = SERVICE_ARGS.get().cloned() {
            let _ = run_audit(args, stop);
        }

        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });
    }

    service_dispatcher::start("FirewallAudit", ffi_service_main)?;
    Ok(())
}
