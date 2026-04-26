// PCAP file writing is handled inline in capture/mod.rs via pcap::Savefile.
// This module is reserved for future JSON/NDJSON export functionality.

use std::fs::File;
use std::io::{BufWriter, Write};

use crate::decode::PacketInfo;

#[allow(dead_code)]
pub struct NdjsonWriter {
    writer: BufWriter<File>,
}

#[allow(dead_code)]
impl NdjsonWriter {
    pub fn open(path: &str) -> std::io::Result<Self> {
        let file = File::create(path)?;
        Ok(Self { writer: BufWriter::new(file) })
    }

    pub fn write_packet(&mut self, p: &PacketInfo) -> std::io::Result<()> {
        let line = format!(
            r#"{{"ts":"{}","src":"{}","dst":"{}","proto":"{}","len":{},"encap":"{}"}}"#,
            p.ts.format("%Y-%m-%dT%H:%M:%S%.3f"),
            p.src.display(),
            p.dst.display(),
            p.proto_label(),
            p.wire_len,
            p.encap_str(),
        );
        writeln!(self.writer, "{}", line)
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}
