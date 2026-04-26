use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "flowfinder", about = "Real-time network packet capture and analysis TUI")]
pub struct Cli {
    /// Network interface to capture on (default: first non-loopback)
    #[arg(short, long, value_name = "IFACE")]
    pub interface: Option<String>,

    /// Write captured packets to a .pcap file
    #[arg(short, long = "write", value_name = "FILE")]
    pub write: Option<String>,

    /// Replay from a .pcap file instead of live capture
    #[arg(short = 'r', long = "read", value_name = "FILE")]
    pub read: Option<String>,

    /// Stop after capturing N packets
    #[arg(short = 'n', long, value_name = "N")]
    pub count: Option<u64>,

    /// Print to stdout only, no TUI
    #[arg(long)]
    pub no_tui: bool,

    /// Show extra header detail in TUI
    #[arg(short, long)]
    pub verbose: bool,

    /// BPF filter expression (e.g. "tcp port 443", "host 8.8.8.8")
    #[arg(value_name = "FILTER")]
    pub filter: Option<String>,
}
