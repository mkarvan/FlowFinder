use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::decode::{
    IcmpDetails, Ipv4Details, Ipv6Details, L7Info, TcpDetails, TunnelInfo, VlanInfo,
};
use crate::tui::app::{AppState, FocusPane};

pub fn render(f: &mut Frame, area: Rect, app: &AppState) {
    let focused = app.focus == FocusPane::Detail;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let block = Block::new()
        .borders(Borders::ALL)
        .title(" Flow Detail ")
        .border_style(border_style);

    let Some(p) = app.selected_packet() else {
        let para = Paragraph::new("No packet selected").block(block);
        f.render_widget(para, area);
        return;
    };

    let mut lines: Vec<Line> = Vec::new();

    // Endpoints
    lines.push(Line::from(vec![
        label("Src   "),
        value(&p.src.display()),
        Span::raw("   "),
        label("Dst   "),
        value(&p.dst.display()),
    ]));

    // Resolved hostnames (if observed via DNS).
    let src_host = p.src.ip.as_ref().and_then(|ip| app.resolve_ip(ip));
    let dst_host = p.dst.ip.as_ref().and_then(|ip| app.resolve_ip(ip));
    if src_host.is_some() || dst_host.is_some() {
        lines.push(Line::from(vec![
            label("Host  "),
            Span::styled(
                src_host.unwrap_or("—").to_string(),
                Style::default().fg(Color::LightCyan),
            ),
            Span::raw("   →   "),
            Span::styled(
                dst_host.unwrap_or("—").to_string(),
                Style::default().fg(Color::LightCyan),
            ),
        ]));
    }

    // Encap chain
    lines.push(Line::from(vec![
        label("Encap "),
        Span::styled(
            p.encap_str(),
            Style::default().fg(Color::LightCyan),
        ),
    ]));

    // Timing and size
    lines.push(Line::from(vec![
        label("Time  "),
        value(&p.ts.format("%Y-%m-%d %H:%M:%S%.6f").to_string()),
        Span::raw("   "),
        label("Len "),
        value(&format!("{} bytes (hdr {}B payload {}B)", p.wire_len, p.header_len, p.payload_len)),
    ]));

    // VLAN
    if let Some(ref v) = p.headers.vlan {
        for line in vlan_lines(v) {
            lines.push(line);
        }
    }

    // L3 + IPv4/IPv6 details
    let mut l3_info = p.l3_proto.as_str().to_string();
    if let Some(ttl) = p.ttl {
        l3_info.push_str(&format!("  TTL {}", ttl));
    }
    lines.push(Line::from(vec![label("L3    "), value(&l3_info)]));
    if let Some(ref ip4) = p.headers.ipv4 {
        for line in ipv4_lines(ip4) {
            lines.push(line);
        }
    }
    if let Some(ref ip6) = p.headers.ipv6 {
        for line in ipv6_lines(ip6) {
            lines.push(line);
        }
    }

    // L4 + TCP/ICMP details
    if let Some(ref l4) = p.l4_proto {
        let mut l4_info = l4.as_str().to_string();
        if let Some(ref flags) = p.tcp_flags {
            let f = flags.display();
            if !f.is_empty() {
                l4_info.push_str(&format!("  Flags [{}]", f));
            }
        }
        lines.push(Line::from(vec![label("L4    "), value(&l4_info)]));

        if let Some(ref tcp) = p.headers.tcp {
            for line in tcp_lines(tcp) {
                lines.push(line);
            }
        }
        if let Some(ref icmp) = p.headers.icmp {
            for line in icmp_lines(icmp) {
                lines.push(line);
            }
        }
    }

    // L7 details
    if let Some(ref l7) = p.l7 {
        lines.push(Line::from(vec![
            label("L7    "),
            Span::styled(
                l7.proto_name(),
                Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD),
            ),
        ]));
        for detail_line in l7_detail_lines(l7) {
            lines.push(detail_line);
        }
    }

    // Tunnel info
    if let Some(ref tun) = p.tunnel {
        for line in tunnel_lines(tun) {
            lines.push(line);
        }
    }

    // MAC addresses if present
    if let Some(mac) = p.src.mac {
        lines.push(Line::from(vec![
            label("SrcMAC"),
            value(&format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            )),
        ]));
    }
    if let Some(mac) = p.dst.mac {
        lines.push(Line::from(vec![
            label("DstMAC"),
            value(&format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            )),
        ]));
    }

    // Payload hex+ASCII dump
    if !p.payload_preview.is_empty() {
        lines.push(Line::from(""));
        let header = format!(
            "Payload ({} of {} bytes)",
            p.payload_preview.len(),
            p.payload_len,
        );
        lines.push(Line::from(vec![Span::styled(
            header,
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        )]));
        for hex_line in hex_dump_lines(&p.payload_preview) {
            lines.push(hex_line);
        }
    }

    let para = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

/// Render up to N rows of `offset  hex bytes  |ASCII|` from a byte slice.
fn hex_dump_lines(bytes: &[u8]) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let offset = i * 16;
        let mut hex = String::with_capacity(50);
        for (j, b) in chunk.iter().enumerate() {
            if j == 8 {
                hex.push(' ');
            }
            hex.push_str(&format!("{:02x} ", b));
        }
        // Pad short last line to keep ASCII column aligned
        let target = 16 * 3 + 1;
        while hex.len() < target {
            hex.push(' ');
        }

        let ascii: String = chunk
            .iter()
            .map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '.' })
            .collect();

        lines.push(Line::from(vec![
            Span::styled(
                format!("{:04x}  ", offset),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(hex, Style::default().fg(Color::White)),
            Span::styled(" |", Style::default().fg(Color::DarkGray)),
            Span::styled(ascii, Style::default().fg(Color::LightGreen)),
            Span::styled("|", Style::default().fg(Color::DarkGray)),
        ]));
    }
    lines
}

fn l7_detail_lines(l7: &L7Info) -> Vec<Line<'static>> {
    match l7 {
        L7Info::Dns { query, qtype, answers, is_response } => {
            let mut lines = vec![Line::from(vec![
                label("  Query "),
                value(&format!("{} {}", qtype, query)),
            ])];
            if *is_response && !answers.is_empty() {
                lines.push(Line::from(vec![
                    label("  Ans   "),
                    value(&answers.join(", ")),
                ]));
            }
            lines
        }
        L7Info::Http { method, host, path, status } => {
            let mut lines = Vec::new();
            if let Some(code) = status {
                lines.push(Line::from(vec![label("  Status"), value(&code.to_string())]));
            } else {
                lines.push(Line::from(vec![
                    label("  Method"),
                    value(&format!("{} {}{}", method, host, path)),
                ]));
            }
            lines
        }
        L7Info::Tls { sni, version, handshake } => {
            let mut lines = vec![Line::from(vec![
                label("  Ver   "),
                value(&format!("{} ({})", version, handshake)),
            ])];
            if let Some(ref name) = sni {
                lines.push(Line::from(vec![label("  SNI   "), value(name)]));
            }
            lines
        }
        L7Info::Dhcp { msg_type } => {
            vec![Line::from(vec![label("  Type  "), value(msg_type)])]
        }
        L7Info::Quic { version } => {
            let v = version.map(|n| format!("{:#010x}", n)).unwrap_or_default();
            vec![Line::from(vec![label("  Ver   "), value(&v)])]
        }
        L7Info::Http2 => vec![Line::from(vec![value("HTTP/2 client preface")])],
    }
}

fn tunnel_lines(tun: &TunnelInfo) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            label("Tunnel"),
            Span::styled(
                tun.proto.name(),
                Style::default().fg(Color::LightYellow).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            label("  Outer"),
            value(&format!("{} → {}", tun.outer_src, tun.outer_dst)),
        ]),
    ];
    if let Some(id_str) = tun.id_label() {
        lines.push(Line::from(vec![label("  ID   "), value(&id_str)]));
    }
    lines
}

fn vlan_lines(v: &VlanInfo) -> Vec<Line<'static>> {
    vec![Line::from(vec![
        label("VLAN  "),
        value(&format!("VID {}  PCP {}  DEI {}", v.vid, v.pcp, v.dei as u8)),
    ])]
}

fn ipv4_lines(ip: &Ipv4Details) -> Vec<Line<'static>> {
    let mut frag_flags = Vec::new();
    if ip.df { frag_flags.push("DF"); }
    if ip.mf { frag_flags.push("MF"); }
    let frag_label = if frag_flags.is_empty() { "—".to_string() } else { frag_flags.join(" ") };
    vec![
        Line::from(vec![
            label("  IHL "),
            value(&format!("{}B", ip.ihl_bytes)),
            Span::raw("  "),
            label("DSCP "),
            value(&format!("{:#04x}", ip.dscp)),
            Span::raw("  "),
            label("ECN "),
            value(&format!("{:#04b}", ip.ecn)),
            Span::raw("  "),
            label("Total "),
            value(&format!("{}B", ip.total_len)),
        ]),
        Line::from(vec![
            label("  ID  "),
            value(&format!("{:#06x}", ip.id)),
            Span::raw("  "),
            label("Frag "),
            value(&format!("[{}] off {}", frag_label, ip.frag_offset)),
            Span::raw("  "),
            label("Cksum "),
            value(&format!("{:#06x}", ip.checksum)),
        ]),
    ]
}

fn ipv6_lines(ip: &Ipv6Details) -> Vec<Line<'static>> {
    vec![Line::from(vec![
        label("  TC  "),
        value(&format!("{:#04x}", ip.traffic_class)),
        Span::raw("  "),
        label("FlowLabel "),
        value(&format!("{:#07x}", ip.flow_label)),
        Span::raw("  "),
        label("Plen "),
        value(&format!("{}B", ip.payload_length)),
        Span::raw("  "),
        label("Next "),
        value(&ip.next_header.to_string()),
    ])]
}

fn tcp_lines(t: &TcpDetails) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            label("  Seq "),
            value(&t.seq.to_string()),
            Span::raw("   "),
            label("Ack "),
            value(&t.ack.to_string()),
        ]),
        Line::from(vec![
            label("  Win "),
            value(&t.window.to_string()),
            Span::raw("  "),
            label("DataOff "),
            value(&format!("{}B", t.data_offset_bytes)),
            Span::raw("  "),
            label("UrgPtr "),
            value(&t.urg_ptr.to_string()),
            Span::raw("  "),
            label("Cksum "),
            value(&format!("{:#06x}", t.checksum)),
        ]),
    ];
    let mut opts: Vec<String> = Vec::new();
    if let Some(mss) = t.mss { opts.push(format!("MSS={}", mss)); }
    if let Some(ws) = t.window_scale { opts.push(format!("WS={}", ws)); }
    if t.sack_permitted { opts.push("SACKp".into()); }
    if let Some((tsval, tsecr)) = t.timestamps { opts.push(format!("TS=({},{})", tsval, tsecr)); }
    if !opts.is_empty() {
        lines.push(Line::from(vec![
            label("  Opts"),
            Span::raw(" "),
            value(&opts.join("  ")),
        ]));
    }
    lines
}

fn icmp_lines(i: &IcmpDetails) -> Vec<Line<'static>> {
    let type_str = match i.type_name {
        Some(name) => format!("{} ({})", i.icmp_type, name),
        None => i.icmp_type.to_string(),
    };
    vec![Line::from(vec![
        label("  Type"),
        Span::raw(" "),
        value(&type_str),
        Span::raw("   "),
        label("Code "),
        value(&i.code.to_string()),
        Span::raw("   "),
        label("Cksum "),
        value(&format!("{:#06x}", i.checksum)),
    ])]
}

fn label(s: &str) -> Span<'static> {
    Span::styled(s.to_string(), Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD))
}

fn value(s: &str) -> Span<'static> {
    Span::styled(s.to_string(), Style::default().fg(Color::White))
}
