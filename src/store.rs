use crate::model::{AuditRecord, FlowKey};
use anyhow::{Context, Result};
use csv::{ReaderBuilder, Writer, WriterBuilder};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::BufWriter;
use std::path::Path;

pub struct CsvStore {
    seen: HashSet<FlowKey>,
    writer: Writer<BufWriter<File>>,
}

impl CsvStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating parent directory for {}", path.display()))?;
        }

        let mut seen = HashSet::new();
        let file_exists_and_nonempty = path
            .metadata()
            .map(|m| m.is_file() && m.len() > 0)
            .unwrap_or(false);

        if file_exists_and_nonempty {
            let mut reader = ReaderBuilder::new()
                .has_headers(true)
                .from_path(path)
                .with_context(|| format!("reading existing CSV {}", path.display()))?;
            for result in reader.deserialize::<AuditRecord>() {
                match result {
                    Ok(rec) => {
                        seen.insert(rec.flow_key());
                    }
                    Err(e) => {
                        eprintln!("warning: skipping malformed existing CSV row: {e}");
                    }
                }
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening CSV {} for append", path.display()))?;

        let writer = WriterBuilder::new()
            .has_headers(!file_exists_and_nonempty)
            .from_writer(BufWriter::new(file));

        Ok(Self { seen, writer })
    }

    pub fn record_if_new(&mut self, record: &AuditRecord) -> Result<bool> {
        let key = record.flow_key();
        if !self.seen.insert(key) {
            return Ok(false);
        }
        self.writer.serialize(record)?;
        Ok(true)
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    pub fn unique_count(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn make_record(remote_ip: &str, remote_port: &str, iface: &str) -> AuditRecord {
        AuditRecord {
            direction: "outbound".to_string(),
            protocol: "tcp".to_string(),
            interface: iface.to_string(),
            local_port: "*".to_string(),
            remote_ip: remote_ip.to_string(),
            remote_port: remote_port.to_string(),
            application: "curl".to_string(),
            executable_path: "/usr/bin/curl".to_string(),
            dns_name: String::new(),
        }
    }

    #[test]
    fn test_csv_store_deduplicates_in_memory_and_across_restarts() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        // Remove empty file created by NamedTempFile so header is written cleanly.
        drop(tmp);

        {
            let mut store = CsvStore::open(&path).unwrap();
            let rec1 = make_record("1.1.1.1", "443", "eth0");
            let rec2 = make_record("1.1.1.1", "443", "eth0");
            let rec3 = make_record("1.1.1.1", "443", "tun0");

            assert!(store.record_if_new(&rec1).unwrap());
            assert!(!store.record_if_new(&rec2).unwrap());
            assert!(store.record_if_new(&rec3).unwrap());
            store.flush().unwrap();
            assert_eq!(store.unique_count(), 2);
        }

        // Reopen store and verify existing rows are loaded into `seen`
        {
            let mut store = CsvStore::open(&path).unwrap();
            assert_eq!(store.unique_count(), 2);
            let rec1 = make_record("1.1.1.1", "443", "eth0");
            let rec4 = make_record("8.8.8.8", "53", "eth0");
            assert!(!store.record_if_new(&rec1).unwrap());
            assert!(store.record_if_new(&rec4).unwrap());
            store.flush().unwrap();
            assert_eq!(store.unique_count(), 3);
        }

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        // 1 header + 3 unique rows
        assert_eq!(lines.len(), 4);
        assert!(lines[0].contains("interface"));
    }
}
