mod capture;
mod cli;
mod decode;
mod stats;
mod tui;

use clap::Parser;
use cli::Cli;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let (raw_tx, raw_rx) = crossbeam_channel::unbounded();
    let (filter_tx, filter_rx) = crossbeam_channel::unbounded::<Option<String>>();
    let (err_tx, err_rx) = crossbeam_channel::unbounded::<String>();

    let interface_name = cli.interface.clone().unwrap_or_else(|| {
        pcap::Device::lookup()
            .ok()
            .flatten()
            .map(|d| d.name)
            .unwrap_or_else(|| "unknown".to_string())
    });

    capture::start_capture(
        cli.interface.clone(),
        cli.read.clone(),
        cli.filter.clone(),
        cli.write.clone(),
        cli.count,
        raw_tx,
        filter_rx,
        err_tx,
    );

    if cli.no_tui {
        run_plain(raw_rx, cli.verbose)?;
    } else {
        tui::run(interface_name, raw_rx, filter_tx, err_rx)?;
    }

    Ok(())
}

fn run_plain(
    raw_rx: crossbeam_channel::Receiver<decode::RawPacket>,
    verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    for raw in raw_rx {
        let p = decode::decode(&raw);
        if verbose {
            println!(
                "{} {} → {} [{}] len={} encap={} {}",
                p.ts.format("%H:%M:%S%.3f"),
                p.src.display(),
                p.dst.display(),
                p.proto_label(),
                p.wire_len,
                p.encap_str(),
                p.l7.as_ref().map(|l| l.summary()).unwrap_or_default()
            );
        } else {
            println!(
                "{} {} → {} {} {}B {}",
                p.ts.format("%H:%M:%S%.3f"),
                p.src.display(),
                p.dst.display(),
                p.proto_label(),
                p.wire_len,
                p.l7.as_ref().map(|l| l.summary()).unwrap_or_default()
            );
        }
    }
    Ok(())
}
