use crate::model::RawConnectionEvent;
use anyhow::Result;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::Arc;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

pub fn start_collector(tx: Sender<RawConnectionEvent>, stop: Arc<AtomicBool>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::start_collector(tx, stop)
    }
    #[cfg(target_os = "macos")]
    {
        macos::start_collector(tx, stop)
    }
    #[cfg(target_os = "windows")]
    {
        windows::start_collector(tx, stop)
    }
}
