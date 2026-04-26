pub mod writer;

use crossbeam_channel::{Receiver, Sender};
use pcap::{Capture, Device};

use crate::decode::RawPacket;

pub fn start_capture(
    interface: Option<String>,
    read_file: Option<String>,
    filter: Option<String>,
    write_file: Option<String>,
    count: Option<u64>,
    tx: Sender<RawPacket>,
    filter_rx: Receiver<Option<String>>,
    err_tx: Sender<String>,
) {
    std::thread::spawn(move || {
        let result = if let Some(path) = read_file {
            // filter_rx/err_tx are not used in offline replay; drop them
            drop(filter_rx);
            drop(err_tx);
            run_offline(path, filter, count, tx)
        } else {
            run_live(interface, filter, write_file, count, tx, filter_rx, err_tx)
        };
        if let Err(e) = result {
            eprintln!("Capture error: {}", e);
        }
    });
}

fn run_live(
    interface: Option<String>,
    filter: Option<String>,
    write_file: Option<String>,
    count: Option<u64>,
    tx: Sender<RawPacket>,
    filter_rx: Receiver<Option<String>>,
    err_tx: Sender<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let device = if let Some(iface) = interface {
        Device::from(iface.as_str())
    } else {
        Device::lookup()?.ok_or("No network device found")?
    };

    let datalink_type;
    let mut cap = Capture::from_device(device)?
        .timeout(100)
        .snaplen(65535)
        .promisc(true)
        .open()?;

    if let Some(ref expr) = filter {
        cap.filter(expr, true)?;
    }

    datalink_type = cap.get_datalink().0;

    let mut savefile = if let Some(ref path) = write_file {
        Some(cap.savefile(path)?)
    } else {
        None
    };

    let mut captured: u64 = 0;
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(ref mut sf) = savefile {
                    sf.write(&packet);
                }
                let raw = RawPacket {
                    data: packet.data.to_vec(),
                    ts_sec: packet.header.ts.tv_sec as i64,
                    ts_usec: packet.header.ts.tv_usec as i64,
                    _caplen: packet.header.caplen,
                    origlen: packet.header.len,
                    datalink: datalink_type,
                };
                if tx.send(raw).is_err() {
                    break;
                }
                captured += 1;
                if let Some(n) = count {
                    if captured >= n {
                        break;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                if let Ok(new_filter) = filter_rx.try_recv() {
                    let expr = new_filter.as_deref().unwrap_or("");
                    if let Err(e) = cap.filter(expr, true) {
                        let _ = err_tx.send(e.to_string());
                    }
                }
            }
            Err(e) => {
                eprintln!("pcap error: {}", e);
                break;
            }
        }
    }
    Ok(())
}

fn run_offline(
    path: String,
    filter: Option<String>,
    count: Option<u64>,
    tx: Sender<RawPacket>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut cap = Capture::from_file(&path)?;

    if let Some(ref expr) = filter {
        cap.filter(expr, true)?;
    }

    let datalink_type = cap.get_datalink().0;
    let mut captured: u64 = 0;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                let raw = RawPacket {
                    data: packet.data.to_vec(),
                    ts_sec: packet.header.ts.tv_sec as i64,
                    ts_usec: packet.header.ts.tv_usec as i64,
                    _caplen: packet.header.caplen,
                    origlen: packet.header.len,
                    datalink: datalink_type,
                };
                if tx.send(raw).is_err() {
                    break;
                }
                captured += 1;
                if let Some(n) = count {
                    if captured >= n {
                        break;
                    }
                }
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                eprintln!("pcap error: {}", e);
                break;
            }
        }
    }
    Ok(())
}
