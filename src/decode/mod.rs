pub mod application;

use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub data: Vec<u8>,
    pub ts_sec: i64,
    pub ts_usec: i64,
    pub _caplen: u32,
    pub origlen: u32,
    pub datalink: i32,
}

#[derive(Debug, Clone, Default)]
pub struct Endpoint {
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
    pub mac: Option<[u8; 6]>,
}

impl Endpoint {
    pub fn display(&self) -> String {
        match (&self.ip, &self.port) {
            (Some(ip), Some(port)) => format!("{}:{}", ip, port),
            (Some(ip), None) => ip.to_string(),
            (None, Some(port)) => format!(":{}", port),
            (None, None) => {
                if let Some(mac) = self.mac {
                    format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                    )
                } else {
                    "?".to_string()
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum L3Proto {
    Ipv4,
    Ipv6,
    Arp,
    Other(u16),
}

impl L3Proto {
    pub fn as_str(&self) -> &str {
        match self {
            L3Proto::Ipv4 => "IPv4",
            L3Proto::Ipv6 => "IPv6",
            L3Proto::Arp => "ARP",
            L3Proto::Other(_) => "L3?",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum L4Proto {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other(u8),
}

impl L4Proto {
    pub fn as_str(&self) -> &str {
        match self {
            L4Proto::Tcp => "TCP",
            L4Proto::Udp => "UDP",
            L4Proto::Icmp => "ICMP",
            L4Proto::Icmpv6 => "ICMPv6",
            L4Proto::Other(_) => "L4?",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
    pub ns: bool,
}

impl TcpFlags {
    pub fn display(&self) -> String {
        let mut flags = Vec::new();
        if self.syn { flags.push("SYN"); }
        if self.ack { flags.push("ACK"); }
        if self.fin { flags.push("FIN"); }
        if self.rst { flags.push("RST"); }
        if self.psh { flags.push("PSH"); }
        if self.urg { flags.push("URG"); }
        if self.ece { flags.push("ECE"); }
        if self.cwr { flags.push("CWR"); }
        if self.ns  { flags.push("NS"); }
        flags.join(" ")
    }
}

#[derive(Debug, Clone)]
pub struct VlanInfo {
    pub vid: u16,
    pub pcp: u8,
    pub dei: bool,
}

#[derive(Debug, Clone)]
pub struct Ipv4Details {
    pub ihl_bytes: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_len: u16,
    pub id: u16,
    pub df: bool,
    pub mf: bool,
    pub frag_offset: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone)]
pub struct Ipv6Details {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
}

#[derive(Debug, Clone)]
pub struct TcpDetails {
    pub seq: u32,
    pub ack: u32,
    pub data_offset_bytes: u8,
    pub window: u16,
    pub checksum: u16,
    pub urg_ptr: u16,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    pub sack_permitted: bool,
    pub timestamps: Option<(u32, u32)>,
}

#[derive(Debug, Clone)]
pub struct IcmpDetails {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub type_name: Option<&'static str>,
}

#[derive(Debug, Clone, Default)]
pub struct Headers {
    pub vlan: Option<VlanInfo>,
    pub ipv4: Option<Ipv4Details>,
    pub ipv6: Option<Ipv6Details>,
    pub tcp: Option<TcpDetails>,
    pub icmp: Option<IcmpDetails>,
}

#[derive(Debug, Clone)]
pub enum L7Info {
    Dns {
        query: String,
        qtype: String,
        answers: Vec<String>,
        is_response: bool,
    },
    Http {
        method: String,
        host: String,
        path: String,
        status: Option<u16>,
    },
    Tls {
        sni: Option<String>,
        version: String,
        handshake: String,
    },
    Dhcp {
        msg_type: String,
    },
    Quic {
        version: Option<u32>,
    },
    Http2,
}

impl L7Info {
    pub fn proto_name(&self) -> &str {
        match self {
            L7Info::Dns { .. } => "DNS",
            L7Info::Http { .. } => "HTTP",
            L7Info::Tls { .. } => "TLS",
            L7Info::Dhcp { .. } => "DHCP",
            L7Info::Quic { .. } => "QUIC",
            L7Info::Http2 => "HTTP/2",
        }
    }

    pub fn summary(&self) -> String {
        match self {
            L7Info::Dns { query, qtype, answers, is_response } => {
                if *is_response && !answers.is_empty() {
                    format!("{} {} → {}", qtype, query, answers.join(", "))
                } else {
                    format!("{} {}?", qtype, query)
                }
            }
            L7Info::Http { method, host, path, status } => {
                if let Some(code) = status {
                    format!("HTTP {} {}", code, method)
                } else {
                    format!("{} {}{}", method, host, path)
                }
            }
            L7Info::Tls { sni, version, handshake } => {
                if let Some(name) = sni {
                    format!("{} SNI={}", version, name)
                } else {
                    format!("{} {}", version, handshake)
                }
            }
            L7Info::Dhcp { msg_type } => format!("DHCP {}", msg_type),
            L7Info::Quic { version } => {
                if let Some(v) = version {
                    format!("QUIC v{:#010x}", v)
                } else {
                    "QUIC".to_string()
                }
            }
            L7Info::Http2 => "HTTP/2".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelProto {
    Gre,
    IpIp,
    Ipv6InIp,
    Vxlan,
}

impl TunnelProto {
    pub fn name(&self) -> &'static str {
        match self {
            TunnelProto::Gre => "GRE",
            TunnelProto::IpIp => "IPIP",
            TunnelProto::Ipv6InIp => "IPv6-in-IPv4",
            TunnelProto::Vxlan => "VXLAN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TunnelInfo {
    pub proto: TunnelProto,
    pub outer_src: IpAddr,
    pub outer_dst: IpAddr,
    pub tunnel_id: Option<u32>,
}

impl TunnelInfo {
    pub fn id_label(&self) -> Option<String> {
        self.tunnel_id.map(|id| match self.proto {
            TunnelProto::Vxlan => format!("VNI {}", id),
            TunnelProto::Gre => format!("Key {:#010x}", id),
            _ => id.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub ts: chrono::DateTime<chrono::Local>,
    pub wire_len: usize,
    pub encap_chain: Vec<String>,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub l3_proto: L3Proto,
    pub l4_proto: Option<L4Proto>,
    pub ttl: Option<u8>,
    pub header_len: usize,
    pub payload_len: usize,
    pub tcp_flags: Option<TcpFlags>,
    pub l7: Option<L7Info>,
    pub tunnel: Option<TunnelInfo>,
    /// First N bytes of the L7 payload, for hex/ASCII display in the UI.
    pub payload_preview: Vec<u8>,
    /// Per-protocol header detail (VLAN, IPv4, IPv6, TCP, ICMP).
    pub headers: Headers,
}

pub const PAYLOAD_PREVIEW_MAX: usize = 128;

impl PacketInfo {
    pub fn proto_label(&self) -> String {
        if let Some(ref l7) = self.l7 {
            l7.proto_name().to_string()
        } else if let Some(ref l4) = self.l4_proto {
            l4.as_str().to_string()
        } else {
            self.l3_proto.as_str().to_string()
        }
    }

    pub fn encap_str(&self) -> String {
        self.encap_chain.join("→")
    }
}

pub fn decode(raw: &RawPacket) -> PacketInfo {
    let mut encap: Vec<String> = Vec::new();
    let mut src = Endpoint::default();
    let mut dst = Endpoint::default();
    let mut l3_proto = L3Proto::Other(0);
    let mut l4_proto: Option<L4Proto> = None;
    let mut ttl: Option<u8> = None;
    let mut header_len: usize = 0;
    let mut payload_len: usize = 0;
    let mut tcp_flags: Option<TcpFlags> = None;
    let mut l7: Option<L7Info> = None;
    let mut tunnel: Option<TunnelInfo> = None;
    let mut headers = Headers::default();

    // DLT_EN10MB = 1, DLT_NULL = 0, DLT_LOOP = 108, DLT_RAW = 101/12
    let ip_data: Option<&[u8]> = match raw.datalink {
        1 => {
            // Ethernet
            parse_ethernet(&raw.data, &mut encap, &mut src, &mut dst, &mut header_len, &mut headers);
            let off = ethernet_header_len(&raw.data);
            if raw.data.len() > off { Some(&raw.data[off..]) } else { None }
        }
        0 | 108 => {
            // BSD null/loopback: 4-byte AF family + IP
            if raw.data.len() > 4 {
                encap.push("Loopback".to_string());
                header_len += 4;
                Some(&raw.data[4..])
            } else {
                None
            }
        }
        101 | 12 | 14 => {
            // Raw IP
            Some(&raw.data)
        }
        _ => {
            // Try ethernet anyway
            parse_ethernet(&raw.data, &mut encap, &mut src, &mut dst, &mut header_len, &mut headers);
            let off = ethernet_header_len(&raw.data);
            if raw.data.len() > off { Some(&raw.data[off..]) } else { None }
        }
    };

    if let Some(ip_bytes) = ip_data {
        parse_ip(
            ip_bytes,
            &mut encap,
            &mut src,
            &mut dst,
            &mut l3_proto,
            &mut l4_proto,
            &mut ttl,
            &mut header_len,
            &mut payload_len,
            &mut tcp_flags,
            &mut l7,
            &mut tunnel,
            &mut headers,
        );
    }

    use chrono::TimeZone;
    let ts = chrono::Local
        .timestamp_opt(raw.ts_sec, (raw.ts_usec * 1000) as u32)
        .single()
        .unwrap_or_else(chrono::Local::now);

    let payload_preview = if header_len < raw.data.len() {
        let end = (header_len + PAYLOAD_PREVIEW_MAX).min(raw.data.len());
        raw.data[header_len..end].to_vec()
    } else {
        Vec::new()
    };

    PacketInfo {
        ts,
        wire_len: raw.origlen as usize,
        encap_chain: encap,
        src,
        dst,
        l3_proto,
        l4_proto,
        ttl,
        header_len,
        payload_len,
        tcp_flags,
        l7,
        tunnel,
        payload_preview,
        headers,
    }
}

fn ethernet_header_len(data: &[u8]) -> usize {
    if data.len() < 14 {
        return 0;
    }
    let etype = u16::from_be_bytes([data[12], data[13]]);
    if etype == 0x8100 && data.len() >= 18 { 18 } else { 14 }
}

fn parse_ethernet(
    data: &[u8],
    encap: &mut Vec<String>,
    src: &mut Endpoint,
    dst: &mut Endpoint,
    header_len: &mut usize,
    headers: &mut Headers,
) {
    if data.len() < 14 {
        return;
    }
    encap.push("Ethernet".to_string());
    *header_len += 14;
    dst.mac = Some(data[0..6].try_into().unwrap_or_default());
    src.mac = Some(data[6..12].try_into().unwrap_or_default());
    let etype = u16::from_be_bytes([data[12], data[13]]);
    // VLAN 802.1Q
    if etype == 0x8100 && data.len() >= 18 {
        encap.push("802.1Q".to_string());
        *header_len += 4;
        let tci = u16::from_be_bytes([data[14], data[15]]);
        headers.vlan = Some(VlanInfo {
            pcp: ((tci >> 13) & 0x07) as u8,
            dei: (tci & 0x1000) != 0,
            vid: tci & 0x0fff,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_ip(
    data: &[u8],
    encap: &mut Vec<String>,
    src: &mut Endpoint,
    dst: &mut Endpoint,
    l3_proto: &mut L3Proto,
    l4_proto: &mut Option<L4Proto>,
    ttl: &mut Option<u8>,
    header_len: &mut usize,
    payload_len: &mut usize,
    tcp_flags: &mut Option<TcpFlags>,
    l7: &mut Option<L7Info>,
    tunnel: &mut Option<TunnelInfo>,
    headers: &mut Headers,
) {
    if data.is_empty() {
        return;
    }

    match data[0] >> 4 {
        4 => parse_ipv4(data, encap, src, dst, l3_proto, l4_proto, ttl, header_len, payload_len, tcp_flags, l7, tunnel, headers),
        6 => parse_ipv6(data, encap, src, dst, l3_proto, l4_proto, ttl, header_len, payload_len, tcp_flags, l7, tunnel, headers),
        _ => {
            // ARP (ethertype 0x0806) or unknown
            if data.len() >= 8 {
                let op = u16::from_be_bytes([data[6], data[7]]);
                if data.len() >= 28 {
                    encap.push("ARP".to_string());
                    *l3_proto = L3Proto::Arp;
                    *header_len += 28;
                    if op == 1 || op == 2 {
                        // sender IP at offset 14, target IP at offset 24
                        let sender = std::net::Ipv4Addr::new(data[14], data[15], data[16], data[17]);
                        let target = std::net::Ipv4Addr::new(data[24], data[25], data[26], data[27]);
                        src.ip = Some(IpAddr::V4(sender));
                        dst.ip = Some(IpAddr::V4(target));
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_ipv4(
    data: &[u8],
    encap: &mut Vec<String>,
    src: &mut Endpoint,
    dst: &mut Endpoint,
    l3_proto: &mut L3Proto,
    l4_proto: &mut Option<L4Proto>,
    ttl: &mut Option<u8>,
    header_len: &mut usize,
    payload_len: &mut usize,
    tcp_flags: &mut Option<TcpFlags>,
    l7: &mut Option<L7Info>,
    tunnel: &mut Option<TunnelInfo>,
    headers: &mut Headers,
) {
    if data.len() < 20 {
        return;
    }
    encap.push("IPv4".to_string());
    *l3_proto = L3Proto::Ipv4;
    let ihl = ((data[0] & 0x0f) * 4) as usize;
    *header_len += ihl;
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    *ttl = Some(data[8]);
    let proto = data[9];
    src.ip = Some(IpAddr::V4(std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15])));
    dst.ip = Some(IpAddr::V4(std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19])));

    let flags_frag = u16::from_be_bytes([data[6], data[7]]);
    headers.ipv4 = Some(Ipv4Details {
        ihl_bytes: ihl as u8,
        dscp: data[1] >> 2,
        ecn: data[1] & 0x03,
        total_len: total_len as u16,
        id: u16::from_be_bytes([data[4], data[5]]),
        df: flags_frag & 0x4000 != 0,
        mf: flags_frag & 0x2000 != 0,
        frag_offset: (flags_frag & 0x1fff) * 8,
        checksum: u16::from_be_bytes([data[10], data[11]]),
    });

    if ihl <= total_len && ihl <= data.len() {
        let transport_data = &data[ihl..];
        let transport_len = total_len.saturating_sub(ihl);
        parse_transport(proto, transport_data, transport_len, encap, src, dst, l3_proto, l4_proto, ttl, header_len, payload_len, tcp_flags, l7, tunnel, headers);
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_ipv6(
    data: &[u8],
    encap: &mut Vec<String>,
    src: &mut Endpoint,
    dst: &mut Endpoint,
    l3_proto: &mut L3Proto,
    l4_proto: &mut Option<L4Proto>,
    ttl: &mut Option<u8>,
    header_len: &mut usize,
    payload_len: &mut usize,
    tcp_flags: &mut Option<TcpFlags>,
    l7: &mut Option<L7Info>,
    tunnel: &mut Option<TunnelInfo>,
    headers: &mut Headers,
) {
    if data.len() < 40 {
        return;
    }
    encap.push("IPv6".to_string());
    *l3_proto = L3Proto::Ipv6;
    *header_len += 40;
    let payload_length = u16::from_be_bytes([data[4], data[5]]) as usize;
    *ttl = Some(data[7]); // hop limit
    let next_header = data[6];

    let traffic_class = ((data[0] & 0x0f) << 4) | (data[1] >> 4);
    let flow_label = ((data[1] as u32 & 0x0f) << 16)
        | ((data[2] as u32) << 8)
        | (data[3] as u32);
    headers.ipv6 = Some(Ipv6Details {
        traffic_class,
        flow_label,
        payload_length: payload_length as u16,
        next_header,
    });

    let src_bytes: [u8; 16] = data[8..24].try_into().unwrap_or_default();
    let dst_bytes: [u8; 16] = data[24..40].try_into().unwrap_or_default();
    src.ip = Some(IpAddr::V6(std::net::Ipv6Addr::from(src_bytes)));
    dst.ip = Some(IpAddr::V6(std::net::Ipv6Addr::from(dst_bytes)));

    if data.len() >= 40 {
        let transport_data = &data[40..];
        parse_transport(next_header, transport_data, payload_length, encap, src, dst, l3_proto, l4_proto, ttl, header_len, payload_len, tcp_flags, l7, tunnel, headers);
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_transport(
    proto: u8,
    data: &[u8],
    transport_len: usize,
    encap: &mut Vec<String>,
    src: &mut Endpoint,
    dst: &mut Endpoint,
    l3_proto: &mut L3Proto,
    l4_proto: &mut Option<L4Proto>,
    ttl: &mut Option<u8>,
    header_len: &mut usize,
    payload_len: &mut usize,
    tcp_flags: &mut Option<TcpFlags>,
    l7: &mut Option<L7Info>,
    tunnel: &mut Option<TunnelInfo>,
    headers: &mut Headers,
) {
    match proto {
        6 => {
            // TCP
            if data.len() < 20 {
                return;
            }
            encap.push("TCP".to_string());
            *l4_proto = Some(L4Proto::Tcp);
            let sport = u16::from_be_bytes([data[0], data[1]]);
            let dport = u16::from_be_bytes([data[2], data[3]]);
            src.port = Some(sport);
            dst.port = Some(dport);
            let data_offset = ((data[12] >> 4) * 4) as usize;
            let flags_byte = data[13];
            *tcp_flags = Some(TcpFlags {
                fin: flags_byte & 0x01 != 0,
                syn: flags_byte & 0x02 != 0,
                rst: flags_byte & 0x04 != 0,
                psh: flags_byte & 0x08 != 0,
                ack: flags_byte & 0x10 != 0,
                urg: flags_byte & 0x20 != 0,
                ece: flags_byte & 0x40 != 0,
                cwr: flags_byte & 0x80 != 0,
                ns:  data[12]    & 0x01 != 0,
            });

            let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            let window = u16::from_be_bytes([data[14], data[15]]);
            let checksum = u16::from_be_bytes([data[16], data[17]]);
            let urg_ptr = u16::from_be_bytes([data[18], data[19]]);
            let (mss, window_scale, sack_permitted, timestamps) =
                parse_tcp_options(&data[20..data_offset.min(data.len())]);
            headers.tcp = Some(TcpDetails {
                seq, ack, data_offset_bytes: data_offset as u8,
                window, checksum, urg_ptr,
                mss, window_scale, sack_permitted, timestamps,
            });

            *header_len += data_offset;
            *payload_len = transport_len.saturating_sub(data_offset);
            let app_data = &data[data_offset.min(data.len())..];
            *l7 = application::decode_l7_tcp(sport, dport, app_data);
            if let Some(ref info) = l7 {
                encap.push(info.proto_name().to_string());
            }
        }
        17 => {
            // UDP
            if data.len() < 8 {
                return;
            }
            encap.push("UDP".to_string());
            *l4_proto = Some(L4Proto::Udp);
            let sport = u16::from_be_bytes([data[0], data[1]]);
            let dport = u16::from_be_bytes([data[2], data[3]]);
            src.port = Some(sport);
            dst.port = Some(dport);
            let udp_len = u16::from_be_bytes([data[4], data[5]]) as usize;
            *header_len += 8;
            *payload_len = udp_len.saturating_sub(8);
            let app_data = &data[8.min(data.len())..];

            // VXLAN (port 4789): outer UDP wraps inner Ethernet frame
            if (sport == 4789 || dport == 4789) && app_data.len() >= 8 {
                let outer_src_ip = src.ip;
                let outer_dst_ip = dst.ip;
                let vni_valid = app_data[0] & 0x08 != 0;
                let vni = ((app_data[4] as u32) << 16)
                    | ((app_data[5] as u32) << 8)
                    | (app_data[6] as u32);
                encap.push("VXLAN".to_string());
                src.port = None;
                dst.port = None;
                if let (Some(osrc), Some(odst)) = (outer_src_ip, outer_dst_ip) {
                    *tunnel = Some(TunnelInfo {
                        proto: TunnelProto::Vxlan,
                        outer_src: osrc,
                        outer_dst: odst,
                        tunnel_id: if vni_valid { Some(vni) } else { None },
                    });
                }
                let inner_eth = &app_data[8..];
                if inner_eth.len() > 14 {
                    encap.push("Ethernet".to_string());
                    let mut inner_tunnel = None;
                    parse_ip(
                        &inner_eth[14..],
                        encap, src, dst, l3_proto, l4_proto, ttl,
                        header_len, payload_len, tcp_flags, l7,
                        &mut inner_tunnel, headers,
                    );
                }
                return;
            }

            *l7 = application::decode_l7_udp(sport, dport, app_data);
            if let Some(ref info) = l7 {
                encap.push(info.proto_name().to_string());
            }
        }
        1 => {
            // ICMPv4
            encap.push("ICMP".to_string());
            *l4_proto = Some(L4Proto::Icmp);
            *header_len += 8;
            *payload_len = transport_len.saturating_sub(8);
            if data.len() >= 4 {
                let t = data[0];
                let code = data[1];
                headers.icmp = Some(IcmpDetails {
                    icmp_type: t,
                    code,
                    checksum: u16::from_be_bytes([data[2], data[3]]),
                    type_name: icmpv4_type_name(t),
                });
            }
        }
        58 => {
            // ICMPv6
            encap.push("ICMPv6".to_string());
            *l4_proto = Some(L4Proto::Icmpv6);
            *header_len += 8;
            *payload_len = transport_len.saturating_sub(8);
            if data.len() >= 4 {
                let t = data[0];
                let code = data[1];
                headers.icmp = Some(IcmpDetails {
                    icmp_type: t,
                    code,
                    checksum: u16::from_be_bytes([data[2], data[3]]),
                    type_name: icmpv6_type_name(t),
                });
            }
        }
        // IP-in-IP (proto 4): outer IPv4 wraps inner IPv4
        4 => {
            let outer_src_ip = src.ip;
            let outer_dst_ip = dst.ip;
            encap.push("IPIP".to_string());
            src.port = None;
            dst.port = None;
            if let (Some(osrc), Some(odst)) = (outer_src_ip, outer_dst_ip) {
                *tunnel = Some(TunnelInfo {
                    proto: TunnelProto::IpIp,
                    outer_src: osrc,
                    outer_dst: odst,
                    tunnel_id: None,
                });
            }
            let mut inner_tunnel = None;
            parse_ip(data, encap, src, dst, l3_proto, l4_proto, ttl, header_len, payload_len, tcp_flags, l7, &mut inner_tunnel, headers);
        }
        // IPv6-in-IPv4 (proto 41): 6in4 tunnel
        41 => {
            let outer_src_ip = src.ip;
            let outer_dst_ip = dst.ip;
            encap.push("6in4".to_string());
            src.port = None;
            dst.port = None;
            if let (Some(osrc), Some(odst)) = (outer_src_ip, outer_dst_ip) {
                *tunnel = Some(TunnelInfo {
                    proto: TunnelProto::Ipv6InIp,
                    outer_src: osrc,
                    outer_dst: odst,
                    tunnel_id: None,
                });
            }
            let mut inner_tunnel = None;
            parse_ip(data, encap, src, dst, l3_proto, l4_proto, ttl, header_len, payload_len, tcp_flags, l7, &mut inner_tunnel, headers);
        }
        // GRE (proto 47): Generic Routing Encapsulation
        47 => {
            if data.len() < 4 {
                *l4_proto = Some(L4Proto::Other(47));
                return;
            }
            let gre_flags = u16::from_be_bytes([data[0], data[1]]);
            let proto_type = u16::from_be_bytes([data[2], data[3]]);
            let checksum_present = gre_flags & 0x8000 != 0;
            let key_present     = gre_flags & 0x2000 != 0;
            let seq_present     = gre_flags & 0x1000 != 0;

            let mut offset = 4usize;
            if checksum_present { offset = offset.saturating_add(4); }
            let gre_key = if key_present && data.len() >= offset + 4 {
                let k = u32::from_be_bytes([
                    data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                ]);
                offset += 4;
                Some(k)
            } else {
                if key_present { offset = offset.saturating_add(4); }
                None
            };
            if seq_present { offset = offset.saturating_add(4); }

            let outer_src_ip = src.ip;
            let outer_dst_ip = dst.ip;
            encap.push("GRE".to_string());
            src.port = None;
            dst.port = None;
            if let (Some(osrc), Some(odst)) = (outer_src_ip, outer_dst_ip) {
                *tunnel = Some(TunnelInfo {
                    proto: TunnelProto::Gre,
                    outer_src: osrc,
                    outer_dst: odst,
                    tunnel_id: gre_key,
                });
            }

            if offset < data.len() {
                let inner = &data[offset..];
                let mut inner_tunnel = None;
                match proto_type {
                    0x0800 | 0x86DD => {
                        parse_ip(inner, encap, src, dst, l3_proto, l4_proto, ttl, header_len, payload_len, tcp_flags, l7, &mut inner_tunnel, headers);
                    }
                    0x6558 => {
                        // Transparent Ethernet Bridging in GRE
                        if inner.len() > 14 {
                            encap.push("Ethernet".to_string());
                            parse_ip(&inner[14..], encap, src, dst, l3_proto, l4_proto, ttl, header_len, payload_len, tcp_flags, l7, &mut inner_tunnel, headers);
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {
            *l4_proto = Some(L4Proto::Other(proto));
        }
    }
}

/// Parse TCP options between bytes 20 and `data_offset*4`.
/// Recognised: MSS (kind 2), WindowScale (kind 3), SACKp (kind 4), Timestamps (kind 8).
fn parse_tcp_options(opts: &[u8]) -> (Option<u16>, Option<u8>, bool, Option<(u32, u32)>) {
    let mut mss = None;
    let mut window_scale = None;
    let mut sack_permitted = false;
    let mut timestamps = None;

    let mut i = 0;
    while i < opts.len() {
        let kind = opts[i];
        if kind == 0 { break; }            // EOL
        if kind == 1 { i += 1; continue; } // NOP
        if i + 1 >= opts.len() { break; }
        let len = opts[i + 1] as usize;
        if len < 2 || i + len > opts.len() { break; }
        match (kind, len) {
            (2, 4) => mss = Some(u16::from_be_bytes([opts[i + 2], opts[i + 3]])),
            (3, 3) => window_scale = Some(opts[i + 2]),
            (4, 2) => sack_permitted = true,
            (8, 10) => {
                let tsval = u32::from_be_bytes([opts[i + 2], opts[i + 3], opts[i + 4], opts[i + 5]]);
                let tsecr = u32::from_be_bytes([opts[i + 6], opts[i + 7], opts[i + 8], opts[i + 9]]);
                timestamps = Some((tsval, tsecr));
            }
            _ => {}
        }
        i += len;
    }
    (mss, window_scale, sack_permitted, timestamps)
}

fn icmpv4_type_name(t: u8) -> Option<&'static str> {
    match t {
        0 => Some("Echo Reply"),
        3 => Some("Dest Unreachable"),
        4 => Some("Source Quench"),
        5 => Some("Redirect"),
        8 => Some("Echo Request"),
        9 => Some("Router Advertisement"),
        10 => Some("Router Solicitation"),
        11 => Some("Time Exceeded"),
        12 => Some("Parameter Problem"),
        13 => Some("Timestamp Request"),
        14 => Some("Timestamp Reply"),
        _ => None,
    }
}

fn icmpv6_type_name(t: u8) -> Option<&'static str> {
    match t {
        1 => Some("Dest Unreachable"),
        2 => Some("Packet Too Big"),
        3 => Some("Time Exceeded"),
        4 => Some("Parameter Problem"),
        128 => Some("Echo Request"),
        129 => Some("Echo Reply"),
        133 => Some("Router Solicitation"),
        134 => Some("Router Advertisement"),
        135 => Some("Neighbor Solicitation"),
        136 => Some("Neighbor Advertisement"),
        137 => Some("Redirect"),
        _ => None,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // ── packet builders ───────────────────────────────────────────────────────

    /// Ethernet II + IPv4 + TCP packet.
    fn eth_ipv4_tcp(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        sport: u16,
        dport: u16,
        flags: u8, // TCP flags byte
        payload: &[u8],
    ) -> RawPacket {
        let tcp_hdr_len = 20usize;
        let ip_hdr_len = 20usize;
        let total_len = (ip_hdr_len + tcp_hdr_len + payload.len()) as u16;

        let mut data = Vec::new();
        // Ethernet header
        data.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // dst MAC
        data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src MAC
        data.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        // IPv4 header
        data.push(0x45); // ver=4, ihl=5
        data.push(0x00); // DSCP
        data.push((total_len >> 8) as u8);
        data.push((total_len & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x01]); // id
        data.extend_from_slice(&[0x00, 0x00]); // flags/frag
        data.push(64); // TTL
        data.push(6);  // proto TCP
        data.extend_from_slice(&[0x00, 0x00]); // checksum
        data.extend_from_slice(&src_ip);
        data.extend_from_slice(&dst_ip);
        // TCP header
        data.push((sport >> 8) as u8); data.push((sport & 0xff) as u8);
        data.push((dport >> 8) as u8); data.push((dport & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // seq
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
        data.push(0x50); // data offset = 5 (20 bytes), reserved=0
        data.push(flags);
        data.extend_from_slice(&[0xff, 0xff]); // window
        data.extend_from_slice(&[0x00, 0x00]); // checksum
        data.extend_from_slice(&[0x00, 0x00]); // urgent
        data.extend_from_slice(payload);

        RawPacket { data, ts_sec: 1_700_000_000, ts_usec: 123_456, _caplen: 0, origlen: 0, datalink: 1 }
    }

    /// Ethernet II + IPv4 + UDP packet.
    fn eth_ipv4_udp(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        sport: u16,
        dport: u16,
        payload: &[u8],
    ) -> RawPacket {
        let udp_len = (8 + payload.len()) as u16;
        let ip_total = (20 + udp_len) as u16;

        let mut data = Vec::new();
        data.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        data.extend_from_slice(&[0x08, 0x00]);
        data.push(0x45); data.push(0x00);
        data.push((ip_total >> 8) as u8); data.push((ip_total & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        data.push(64); data.push(17); // UDP
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&src_ip);
        data.extend_from_slice(&dst_ip);
        data.push((sport >> 8) as u8); data.push((sport & 0xff) as u8);
        data.push((dport >> 8) as u8); data.push((dport & 0xff) as u8);
        data.push((udp_len >> 8) as u8); data.push((udp_len & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x00]); // checksum
        data.extend_from_slice(payload);

        RawPacket { data, ts_sec: 1_700_000_000, ts_usec: 0, _caplen: 0, origlen: 0, datalink: 1 }
    }

    /// Ethernet II + IPv4 + ICMP echo request.
    fn eth_ipv4_icmp(src_ip: [u8; 4], dst_ip: [u8; 4]) -> RawPacket {
        let ip_total: u16 = 20 + 8 + 32; // IP + ICMP header + data
        let mut data = Vec::new();
        data.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        data.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        data.extend_from_slice(&[0x08, 0x00]);
        data.push(0x45); data.push(0x00);
        data.push((ip_total >> 8) as u8); data.push((ip_total & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        data.push(128); data.push(1); // ICMP
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&src_ip);
        data.extend_from_slice(&dst_ip);
        // ICMP echo request
        data.push(8); data.push(0);  // type=8 (echo request), code=0
        data.extend_from_slice(&[0x00, 0x00]); // checksum
        data.extend_from_slice(&[0x00, 0x01]); // id
        data.extend_from_slice(&[0x00, 0x01]); // seq
        data.extend_from_slice(&[0u8; 32]);   // data

        RawPacket { data, ts_sec: 0, ts_usec: 0, _caplen: 0, origlen: 0, datalink: 1 }
    }

    /// BSD loopback (DLT_NULL) + IPv4 + UDP packet.
    fn loopback_ipv4_udp(sport: u16, dport: u16, payload: &[u8]) -> RawPacket {
        let udp_len = (8 + payload.len()) as u16;
        let ip_total = (20 + udp_len) as u16;

        let mut data = Vec::new();
        // 4-byte BSD null header (AF_INET = 2)
        data.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        // IPv4
        data.push(0x45); data.push(0x00);
        data.push((ip_total >> 8) as u8); data.push((ip_total & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        data.push(64); data.push(17);
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&[127, 0, 0, 1]);
        data.extend_from_slice(&[127, 0, 0, 1]);
        data.push((sport >> 8) as u8); data.push((sport & 0xff) as u8);
        data.push((dport >> 8) as u8); data.push((dport & 0xff) as u8);
        data.push((udp_len >> 8) as u8); data.push((udp_len & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(payload);

        RawPacket { data, ts_sec: 0, ts_usec: 0, _caplen: 0, origlen: 0, datalink: 0 }
    }

    // ── decode tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_decode_ipv4_tcp_syn() {
        let raw = eth_ipv4_tcp(
            [192, 168, 1, 5],
            [8, 8, 8, 8],
            52341,
            443,
            0x02, // SYN
            &[],
        );
        let p = decode(&raw);
        assert_eq!(p.src.ip, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))));
        assert_eq!(p.dst.ip, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert_eq!(p.src.port, Some(52341));
        assert_eq!(p.dst.port, Some(443));
        assert_eq!(p.l3_proto, L3Proto::Ipv4);
        assert_eq!(p.l4_proto, Some(L4Proto::Tcp));
        assert_eq!(p.ttl, Some(64));
        let flags = p.tcp_flags.expect("TCP flags missing");
        assert!(flags.syn);
        assert!(!flags.ack);
        assert!(!flags.fin);
    }

    #[test]
    fn test_decode_ipv4_tcp_syn_ack() {
        let raw = eth_ipv4_tcp(
            [8, 8, 8, 8], [192, 168, 1, 5], 443, 52341,
            0x12, // SYN + ACK
            &[],
        );
        let p = decode(&raw);
        let flags = p.tcp_flags.unwrap();
        assert!(flags.syn);
        assert!(flags.ack);
        assert!(!flags.rst);
    }

    #[test]
    fn test_decode_tcp_all_flags() {
        // URG+ACK+PSH+RST+SYN+FIN = 0x3f
        let raw = eth_ipv4_tcp([1,2,3,4], [5,6,7,8], 1000, 2000, 0x3f, &[]);
        let p = decode(&raw);
        let f = p.tcp_flags.unwrap();
        assert!(f.syn && f.ack && f.fin && f.rst && f.psh && f.urg);
    }

    #[test]
    fn test_decode_tcp_flags_display() {
        let raw = eth_ipv4_tcp([1,2,3,4], [5,6,7,8], 1000, 80, 0x02, &[]);
        let p = decode(&raw);
        let display = p.tcp_flags.unwrap().display();
        assert_eq!(display, "SYN");
    }

    #[test]
    fn test_decode_ipv4_udp() {
        let raw = eth_ipv4_udp(
            [10, 0, 0, 1], [8, 8, 8, 8], 54321, 53, &[0u8; 20]
        );
        let p = decode(&raw);
        assert_eq!(p.l3_proto, L3Proto::Ipv4);
        assert_eq!(p.l4_proto, Some(L4Proto::Udp));
        assert_eq!(p.src.port, Some(54321));
        assert_eq!(p.dst.port, Some(53));
    }

    #[test]
    fn test_decode_icmp() {
        let raw = eth_ipv4_icmp([192, 168, 0, 1], [192, 168, 0, 2]);
        let p = decode(&raw);
        assert_eq!(p.l4_proto, Some(L4Proto::Icmp));
        assert!(p.tcp_flags.is_none());
    }

    #[test]
    fn test_decode_encap_chain_tcp() {
        let raw = eth_ipv4_tcp([1,2,3,4], [5,6,7,8], 80, 54321, 0x10, &[]);
        let p = decode(&raw);
        assert!(p.encap_chain.contains(&"Ethernet".to_string()));
        assert!(p.encap_chain.contains(&"IPv4".to_string()));
        assert!(p.encap_chain.contains(&"TCP".to_string()));
    }

    #[test]
    fn test_decode_encap_chain_udp_dns() {
        let dns_query = {
            let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            q.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0]);
            q.extend_from_slice(&[0, 1, 0, 1]);
            q
        };
        let raw = eth_ipv4_udp([10,0,0,1], [8,8,8,8], 54321, 53, &dns_query);
        let p = decode(&raw);
        assert!(p.encap_chain.contains(&"DNS".to_string()));
        assert!(matches!(p.l7, Some(L7Info::Dns { .. })));
    }

    #[test]
    fn test_decode_http_get() {
        let payload = b"GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let raw = eth_ipv4_tcp([10,0,0,1], [93,184,216,34], 54321, 80, 0x18, payload);
        let p = decode(&raw);
        assert!(matches!(p.l7, Some(L7Info::Http { .. })));
    }

    #[test]
    fn test_decode_mac_addresses() {
        let raw = eth_ipv4_tcp([1,2,3,4], [5,6,7,8], 1000, 2000, 0x02, &[]);
        let p = decode(&raw);
        assert_eq!(p.src.mac, Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
        assert_eq!(p.dst.mac, Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    }

    #[test]
    fn test_decode_header_payload_lengths() {
        // Ethernet(14) + IPv4(20) + TCP(20) = 54 bytes header; payload = 10 bytes
        let payload = vec![0u8; 10];
        let raw = eth_ipv4_tcp([1,2,3,4], [5,6,7,8], 1000, 2000, 0x18, &payload);
        let p = decode(&raw);
        assert_eq!(p.header_len, 14 + 20 + 20); // eth + ip + tcp
        assert_eq!(p.payload_len, 10);
    }

    #[test]
    fn test_decode_loopback_packet() {
        let dns_payload = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x03, b'w', b'w', b'w', 0x00,
                               0x00, 0x01, 0x00, 0x01];
        let raw = loopback_ipv4_udp(54321, 53, &dns_payload);
        let p = decode(&raw);
        assert_eq!(p.l3_proto, L3Proto::Ipv4);
        assert_eq!(p.l4_proto, Some(L4Proto::Udp));
        assert!(p.encap_chain.contains(&"Loopback".to_string()));
    }

    #[test]
    fn test_decode_short_packet_no_panic() {
        let raw = RawPacket { data: vec![0x08, 0x00], ts_sec: 0, ts_usec: 0, _caplen: 0, origlen: 2, datalink: 1 };
        let _ = decode(&raw); // must not panic
    }

    #[test]
    fn test_decode_empty_packet_no_panic() {
        let raw = RawPacket { data: vec![], ts_sec: 0, ts_usec: 0, _caplen: 0, origlen: 0, datalink: 1 };
        let _ = decode(&raw);
    }

    // ── Endpoint::display tests ───────────────────────────────────────────────

    #[test]
    fn test_endpoint_display_ip_and_port() {
        let ep = Endpoint {
            ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            port: Some(443),
            mac: None,
        };
        assert_eq!(ep.display(), "192.168.1.1:443");
    }

    #[test]
    fn test_endpoint_display_ip_only() {
        let ep = Endpoint {
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            port: None,
            mac: None,
        };
        assert_eq!(ep.display(), "10.0.0.1");
    }

    #[test]
    fn test_endpoint_display_mac_fallback() {
        let ep = Endpoint { ip: None, port: None, mac: Some([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]) };
        assert_eq!(ep.display(), "de:ad:be:ef:00:01");
    }

    #[test]
    fn test_endpoint_display_unknown() {
        let ep = Endpoint::default();
        assert_eq!(ep.display(), "?");
    }

    // ── proto_label tests ─────────────────────────────────────────────────────

    #[test]
    fn test_proto_label_prefers_l7() {
        let raw = {
            let dns = {
                let mut q = vec![0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00];
                q.extend_from_slice(&[7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0]);
                q.extend_from_slice(&[0,1,0,1]);
                q
            };
            eth_ipv4_udp([1,2,3,4],[5,6,7,8],54321,53,&dns)
        };
        let p = decode(&raw);
        assert_eq!(p.proto_label(), "DNS");
    }

    #[test]
    fn test_proto_label_falls_back_to_l4() {
        let raw = eth_ipv4_tcp([1,2,3,4],[5,6,7,8],54321,9999,0x02,&[]);
        let p = decode(&raw);
        assert_eq!(p.proto_label(), "TCP");
    }

    #[test]
    fn test_proto_label_falls_back_to_l3_for_icmp() {
        let raw = eth_ipv4_icmp([1,2,3,4],[5,6,7,8]);
        let p = decode(&raw);
        assert_eq!(p.proto_label(), "ICMP");
    }

    // ── tunnel builders ───────────────────────────────────────────────────────

    /// Ethernet + outer IPv4 + inner IPv4 (IPIP, proto 4) + UDP payload.
    fn ipip_packet(
        outer_src: [u8; 4], outer_dst: [u8; 4],
        inner_src: [u8; 4], inner_dst: [u8; 4],
        inner_sport: u16, inner_dport: u16,
    ) -> RawPacket {
        let udp_payload = b"hello";
        let inner_udp_len = (8 + udp_payload.len()) as u16;
        let inner_ip_len = (20 + inner_udp_len as usize) as u16;
        let outer_ip_total = (20 + 20 + 8 + udp_payload.len()) as u16;

        let mut data = Vec::new();
        // Outer Ethernet
        data.extend_from_slice(&[0xaa; 6]); // dst MAC
        data.extend_from_slice(&[0xbb; 6]); // src MAC
        data.extend_from_slice(&[0x08, 0x00]); // IPv4
        // Outer IPv4
        data.push(0x45);
        data.push(0x00);
        data.push((outer_ip_total >> 8) as u8); data.push((outer_ip_total & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // id, flags/frag
        data.push(64); // TTL
        data.push(4);  // proto = IPIP
        data.extend_from_slice(&[0x00, 0x00]); // checksum
        data.extend_from_slice(&outer_src);
        data.extend_from_slice(&outer_dst);
        // Inner IPv4
        data.push(0x45);
        data.push(0x00);
        data.push((inner_ip_len >> 8) as u8); data.push((inner_ip_len & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x02, 0x00, 0x00]);
        data.push(128); // inner TTL
        data.push(17);  // UDP
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&inner_src);
        data.extend_from_slice(&inner_dst);
        // Inner UDP
        data.push((inner_sport >> 8) as u8); data.push((inner_sport & 0xff) as u8);
        data.push((inner_dport >> 8) as u8); data.push((inner_dport & 0xff) as u8);
        data.push((inner_udp_len >> 8) as u8); data.push((inner_udp_len & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x00]); // checksum
        data.extend_from_slice(udp_payload);

        RawPacket {
            data,
            ts_sec: 0, ts_usec: 0,
            _caplen: 0, origlen: 0,
            datalink: 1,
        }
    }

    /// Ethernet + outer IPv4 + GRE (no key) + inner IPv4 + ICMP.
    fn gre_packet(
        outer_src: [u8; 4], outer_dst: [u8; 4],
        inner_src: [u8; 4], inner_dst: [u8; 4],
    ) -> RawPacket {
        let inner_icmp_len = 8usize;
        let inner_ip_total = (20 + inner_icmp_len) as u16;
        let outer_ip_total = (20 + 4 + 20 + inner_icmp_len) as u16; // GRE hdr = 4

        let mut data = Vec::new();
        // Outer Ethernet
        data.extend_from_slice(&[0xcc; 6]);
        data.extend_from_slice(&[0xdd; 6]);
        data.extend_from_slice(&[0x08, 0x00]);
        // Outer IPv4
        data.push(0x45); data.push(0x00);
        data.push((outer_ip_total >> 8) as u8); data.push((outer_ip_total & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x03, 0x00, 0x00]);
        data.push(64); data.push(47); // proto = GRE
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&outer_src);
        data.extend_from_slice(&outer_dst);
        // GRE header (no flags, IPv4 payload)
        data.extend_from_slice(&[0x00, 0x00]); // flags = 0
        data.extend_from_slice(&[0x08, 0x00]); // proto = IPv4
        // Inner IPv4
        data.push(0x45); data.push(0x00);
        data.push((inner_ip_total >> 8) as u8); data.push((inner_ip_total & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x04, 0x00, 0x00]);
        data.push(128); data.push(1); // ICMP
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&inner_src);
        data.extend_from_slice(&inner_dst);
        // ICMP echo
        data.extend_from_slice(&[0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]);

        RawPacket {
            data,
            ts_sec: 0, ts_usec: 0,
            _caplen: 0, origlen: 0,
            datalink: 1,
        }
    }

    /// Ethernet + outer IPv4 + UDP + VXLAN + inner Ethernet + inner IPv4 + TCP.
    fn vxlan_packet(
        outer_src: [u8; 4], outer_dst: [u8; 4],
        vni: u32,
        inner_src: [u8; 4], inner_dst: [u8; 4],
        inner_sport: u16, inner_dport: u16,
    ) -> RawPacket {
        let inner_tcp_len = 20usize;
        let inner_ip_total = (20 + inner_tcp_len) as u16;
        // inner Ethernet(14) + inner IPv4(20) + inner TCP(20) = 54
        let inner_eth_frame_len = 14 + 20 + inner_tcp_len;
        let vxlan_payload_len = 8 + inner_eth_frame_len; // VXLAN hdr + inner Ethernet
        let udp_len = (8 + vxlan_payload_len) as u16;
        let outer_ip_total = (20 + udp_len as usize) as u16;

        let mut data = Vec::new();
        // Outer Ethernet
        data.extend_from_slice(&[0x11; 6]);
        data.extend_from_slice(&[0x22; 6]);
        data.extend_from_slice(&[0x08, 0x00]);
        // Outer IPv4
        data.push(0x45); data.push(0x00);
        data.push((outer_ip_total >> 8) as u8); data.push((outer_ip_total & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x05, 0x00, 0x00]);
        data.push(64); data.push(17); // UDP
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&outer_src);
        data.extend_from_slice(&outer_dst);
        // Outer UDP (src arbitrary, dst 4789)
        data.extend_from_slice(&[0xc0, 0x00]); // src port 49152
        data.extend_from_slice(&[0x12, 0xb5]); // dst port 4789
        data.push((udp_len >> 8) as u8); data.push((udp_len & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x00]);
        // VXLAN header: flags (VNI valid = 0x08), reserved(3), VNI(3), reserved(1)
        data.push(0x08); data.extend_from_slice(&[0x00, 0x00, 0x00]);
        data.push(((vni >> 16) & 0xff) as u8);
        data.push(((vni >> 8) & 0xff) as u8);
        data.push((vni & 0xff) as u8);
        data.push(0x00);
        // Inner Ethernet
        data.extend_from_slice(&[0x33; 6]); // dst MAC
        data.extend_from_slice(&[0x44; 6]); // src MAC
        data.extend_from_slice(&[0x08, 0x00]); // IPv4
        // Inner IPv4
        data.push(0x45); data.push(0x00);
        data.push((inner_ip_total >> 8) as u8); data.push((inner_ip_total & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x06, 0x00, 0x00]);
        data.push(64); data.push(6); // TCP
        data.extend_from_slice(&[0x00, 0x00]);
        data.extend_from_slice(&inner_src);
        data.extend_from_slice(&inner_dst);
        // Inner TCP
        data.push((inner_sport >> 8) as u8); data.push((inner_sport & 0xff) as u8);
        data.push((inner_dport >> 8) as u8); data.push((inner_dport & 0xff) as u8);
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // seq
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ack
        data.push(0x50); // data offset = 5 (20 bytes)
        data.push(0x02); // SYN
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // window, checksum, urgent

        RawPacket {
            data,
            ts_sec: 0, ts_usec: 0,
            _caplen: 0, origlen: 0,
            datalink: 1,
        }
    }

    // ── tunnel decode tests ───────────────────────────────────────────────────

    #[test]
    fn test_ipip_tunnel_detected() {
        let raw = ipip_packet(
            [10, 0, 0, 1], [10, 0, 0, 2],
            [192, 168, 1, 1], [192, 168, 1, 2],
            50000, 53,
        );
        let p = decode(&raw);

        let tun = p.tunnel.as_ref().expect("tunnel must be detected for IPIP");
        assert_eq!(tun.proto, TunnelProto::IpIp);
        assert_eq!(tun.outer_src.to_string(), "10.0.0.1");
        assert_eq!(tun.outer_dst.to_string(), "10.0.0.2");
        assert_eq!(tun.tunnel_id, None);

        // Inner endpoints should be visible in packet src/dst
        assert_eq!(p.src.ip.unwrap().to_string(), "192.168.1.1");
        assert_eq!(p.dst.ip.unwrap().to_string(), "192.168.1.2");
        assert_eq!(p.l4_proto, Some(L4Proto::Udp));

        assert!(p.encap_chain.contains(&"IPIP".to_string()));
        assert!(p.encap_chain.contains(&"IPv4".to_string()));
        assert!(p.encap_chain.contains(&"UDP".to_string()));
    }

    #[test]
    fn test_gre_tunnel_detected() {
        let raw = gre_packet(
            [172, 16, 0, 1], [172, 16, 0, 2],
            [10, 1, 1, 1], [10, 1, 1, 2],
        );
        let p = decode(&raw);

        let tun = p.tunnel.as_ref().expect("tunnel must be detected for GRE");
        assert_eq!(tun.proto, TunnelProto::Gre);
        assert_eq!(tun.outer_src.to_string(), "172.16.0.1");
        assert_eq!(tun.outer_dst.to_string(), "172.16.0.2");
        assert_eq!(tun.tunnel_id, None); // no GRE key in this packet

        // Inner ICMP endpoints
        assert_eq!(p.src.ip.unwrap().to_string(), "10.1.1.1");
        assert_eq!(p.dst.ip.unwrap().to_string(), "10.1.1.2");
        assert_eq!(p.l4_proto, Some(L4Proto::Icmp));

        assert!(p.encap_chain.contains(&"GRE".to_string()));
        assert!(p.encap_chain.contains(&"ICMP".to_string()));
    }

    #[test]
    fn test_vxlan_tunnel_detected() {
        let raw = vxlan_packet(
            [192, 168, 100, 1], [192, 168, 100, 2],
            12345,
            [10, 10, 0, 1], [10, 10, 0, 2],
            50001, 80,
        );
        let p = decode(&raw);

        let tun = p.tunnel.as_ref().expect("tunnel must be detected for VXLAN");
        assert_eq!(tun.proto, TunnelProto::Vxlan);
        assert_eq!(tun.outer_src.to_string(), "192.168.100.1");
        assert_eq!(tun.outer_dst.to_string(), "192.168.100.2");
        assert_eq!(tun.tunnel_id, Some(12345));
        assert_eq!(tun.id_label().as_deref(), Some("VNI 12345"));

        // Inner TCP endpoints
        assert_eq!(p.src.ip.unwrap().to_string(), "10.10.0.1");
        assert_eq!(p.dst.ip.unwrap().to_string(), "10.10.0.2");
        assert_eq!(p.src.port, Some(50001));
        assert_eq!(p.dst.port, Some(80));
        assert_eq!(p.l4_proto, Some(L4Proto::Tcp));

        assert!(p.encap_chain.contains(&"VXLAN".to_string()));
        assert!(p.encap_chain.contains(&"TCP".to_string()));
    }

    #[test]
    fn test_non_tunnel_packet_has_no_tunnel_info() {
        let raw = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 12345, 443, 0x02, b"");
        let p = decode(&raw);
        assert!(p.tunnel.is_none());
    }

    // ── header detail tests ───────────────────────────────────────────────────

    #[test]
    fn test_ipv4_details_populated() {
        let raw = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 1000, 80, 0x02, b"");
        let p = decode(&raw);
        let ip = p.headers.ipv4.expect("ipv4 details set for IPv4 packet");
        assert_eq!(ip.ihl_bytes, 20);
        assert_eq!(ip.id, 1);
        assert!(!ip.df);
        assert!(!ip.mf);
        assert_eq!(ip.frag_offset, 0);
    }

    #[test]
    fn test_tcp_details_seq_ack_window_populated() {
        let raw = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 1000, 80, 0x10, b"");
        let p = decode(&raw);
        let tcp = p.headers.tcp.expect("tcp details set for TCP packet");
        assert_eq!(tcp.seq, 1);
        assert_eq!(tcp.ack, 0);
        assert_eq!(tcp.window, 0xffff);
        assert_eq!(tcp.data_offset_bytes, 20);
    }

    #[test]
    fn test_tcp_extended_flags_ece_cwr() {
        // bit 6 = ECE, bit 7 = CWR
        let raw = eth_ipv4_tcp([1, 2, 3, 4], [5, 6, 7, 8], 1000, 80, 0xC0, b"");
        let p = decode(&raw);
        let flags = p.tcp_flags.expect("tcp flags set");
        assert!(flags.ece);
        assert!(flags.cwr);
    }

    #[test]
    fn test_tcp_options_parsed() {
        // MSS=1460, WS=7, SACKp, TS=(0x11223344, 0x55667788)
        let opts = [
            0x02, 0x04, 0x05, 0xb4, // MSS 1460
            0x03, 0x03, 0x07,       // WS 7
            0x04, 0x02,             // SACK permitted
            0x08, 0x0a,
            0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88, // TS
            0x00,                   // EOL
        ];
        let (mss, ws, sackp, ts) = parse_tcp_options(&opts);
        assert_eq!(mss, Some(1460));
        assert_eq!(ws, Some(7));
        assert!(sackp);
        assert_eq!(ts, Some((0x11223344, 0x55667788)));
    }

    #[test]
    fn test_tcp_options_handles_nops() {
        let opts = [0x01, 0x01, 0x02, 0x04, 0x05, 0xb4, 0x00];
        let (mss, _, _, _) = parse_tcp_options(&opts);
        assert_eq!(mss, Some(1460));
    }

    #[test]
    fn test_icmp_details_populated_with_type_name() {
        let raw = eth_ipv4_icmp([1, 2, 3, 4], [5, 6, 7, 8]);
        let p = decode(&raw);
        let icmp = p.headers.icmp.expect("icmp details set for ICMP packet");
        assert_eq!(icmp.icmp_type, 8);
        assert_eq!(icmp.code, 0);
        assert_eq!(icmp.type_name, Some("Echo Request"));
    }

    #[test]
    fn test_vlan_tagged_packet_extracts_vid() {
        // Ethernet + 802.1Q tag (VID=100, PCP=3) + IPv4 + UDP
        let mut data = Vec::new();
        data.extend_from_slice(&[0xaa; 6]);
        data.extend_from_slice(&[0xbb; 6]);
        data.extend_from_slice(&[0x81, 0x00]);                   // VLAN ethertype
        data.extend_from_slice(&[(3 << 5) | 0x00, 0x64]);        // PCP 3, DEI 0, VID 100
        data.extend_from_slice(&[0x08, 0x00]);                   // inner ethertype IPv4
        // Minimal IPv4+UDP
        data.push(0x45); data.push(0x00);
        data.extend_from_slice(&[0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 17, 0x00, 0x00]);
        data.extend_from_slice(&[1, 1, 1, 1, 2, 2, 2, 2]);
        data.extend_from_slice(&[0x00, 0x35, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]);
        let raw = RawPacket { data, ts_sec: 0, ts_usec: 0, _caplen: 0, origlen: 0, datalink: 1 };
        let p = decode(&raw);
        let v = p.headers.vlan.expect("vlan info populated");
        assert_eq!(v.vid, 100);
        assert_eq!(v.pcp, 3);
        assert!(!v.dei);
        assert!(p.encap_chain.contains(&"802.1Q".to_string()));
        assert_eq!(p.l4_proto, Some(L4Proto::Udp));
    }
}
