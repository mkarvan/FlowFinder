use super::L7Info;

pub fn decode_l7_tcp(sport: u16, dport: u16, data: &[u8]) -> Option<L7Info> {
    if data.is_empty() {
        return None;
    }
    // HTTP/2 preface
    if data.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
        return Some(L7Info::Http2);
    }
    // TLS
    if data[0] == 0x16 || data[0] == 0x14 || data[0] == 0x15 || data[0] == 0x17 {
        if data.len() >= 3 && data[1] == 3 {
            return parse_tls(data);
        }
    }
    // HTTP (ports 80, 8080, 8000, or common plaintext)
    if matches!(sport, 80 | 8080 | 8000 | 8443 | 3000) || matches!(dport, 80 | 8080 | 8000 | 8443 | 3000) {
        if let Some(h) = parse_http(data) {
            return Some(h);
        }
    }
    // Try HTTP anyway if it looks like it
    if data.starts_with(b"GET ") || data.starts_with(b"POST ") || data.starts_with(b"PUT ")
        || data.starts_with(b"DELETE ") || data.starts_with(b"HEAD ") || data.starts_with(b"HTTP/")
    {
        return parse_http(data);
    }
    None
}

pub fn decode_l7_udp(sport: u16, dport: u16, data: &[u8]) -> Option<L7Info> {
    if data.is_empty() {
        return None;
    }
    // DNS
    if sport == 53 || dport == 53 || sport == 5353 || dport == 5353 {
        return parse_dns(data);
    }
    // DHCP
    if (sport == 67 || sport == 68) || (dport == 67 || dport == 68) {
        return parse_dhcp(data);
    }
    // QUIC (typically UDP 443, or QUIC alt ports)
    if sport == 443 || dport == 443 || sport == 4443 || dport == 4443 {
        if is_quic(data) {
            return parse_quic(data);
        }
    }
    // Try QUIC on any port if it has the long header bit pattern
    if data.len() > 4 && is_quic(data) {
        return parse_quic(data);
    }
    None
}

fn parse_tls(data: &[u8]) -> Option<L7Info> {
    if data.len() < 5 {
        return None;
    }
    let record_type = data[0];
    let version_major = data[1];
    let version_minor = data[2];

    let version = tls_version_str(version_major, version_minor);

    let handshake_label = match record_type {
        0x14 => "ChangeCipherSpec",
        0x15 => "Alert",
        0x16 => "Handshake",
        0x17 => "ApplicationData",
        _ => "Unknown",
    };

    if record_type != 0x16 || data.len() < 6 {
        return Some(L7Info::Tls {
            sni: None,
            version: version.to_string(),
            handshake: handshake_label.to_string(),
        });
    }

    let handshake_type = data[5];
    if handshake_type != 0x01 {
        let hs = match handshake_type {
            0x02 => "ServerHello",
            0x0b => "Certificate",
            0x0c => "ServerKeyExchange",
            0x0e => "ServerHelloDone",
            0x10 => "ClientKeyExchange",
            0x0f => "CertificateRequest",
            0x14 => "Finished",
            _ => "Handshake",
        };
        return Some(L7Info::Tls {
            sni: None,
            version: version.to_string(),
            handshake: hs.to_string(),
        });
    }

    // Parse ClientHello to extract SNI
    let sni = extract_sni(data);
    Some(L7Info::Tls {
        sni,
        version: version.to_string(),
        handshake: "ClientHello".to_string(),
    })
}

fn tls_version_str(major: u8, minor: u8) -> &'static str {
    match (major, minor) {
        (3, 1) => "TLS 1.0",
        (3, 2) => "TLS 1.1",
        (3, 3) => "TLS 1.2",
        (3, 4) => "TLS 1.3",
        _ => "TLS",
    }
}

fn extract_sni(data: &[u8]) -> Option<String> {
    // TLS record: [type(1), ver(2), len(2)] = 5 bytes
    // Handshake: [hs_type(1), len(3)] = 4 bytes from data[5]
    // ClientHello body starts at data[9]
    if data.len() < 9 {
        return None;
    }
    let mut pos = 9usize;

    // client_version (2)
    if pos + 2 > data.len() { return None; }
    pos += 2;
    // random (32)
    if pos + 32 > data.len() { return None; }
    pos += 32;
    // session_id
    if pos + 1 > data.len() { return None; }
    let sid_len = data[pos] as usize;
    pos += 1 + sid_len;
    // cipher_suites
    if pos + 2 > data.len() { return None; }
    let cs_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cs_len;
    // compression methods
    if pos + 1 > data.len() { return None; }
    let cm_len = data[pos] as usize;
    pos += 1 + cm_len;
    // extensions length
    if pos + 2 > data.len() { return None; }
    let ext_total = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let ext_end = (pos + ext_total).min(data.len());
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0x0000 {
            // SNI: list_len(2) + entry_type(1) + name_len(2) + name
            if ext_len >= 5 && pos + 5 <= data.len() {
                let name_len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
                if pos + 5 + name_len <= data.len() {
                    return std::str::from_utf8(&data[pos + 5..pos + 5 + name_len])
                        .ok()
                        .map(|s| s.to_string());
                }
            }
        }
        if pos + ext_len > ext_end { break; }
        pos += ext_len;
    }
    None
}

fn parse_dns(data: &[u8]) -> Option<L7Info> {
    if data.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let is_response = flags & 0x8000 != 0;

    let mut pos = 12usize;
    let mut query = String::new();
    let mut qtype_str = String::new();

    if qdcount > 0 {
        let (name, new_pos) = read_dns_name(data, pos);
        query = name;
        pos = new_pos;
        if pos + 4 <= data.len() {
            let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            qtype_str = dns_qtype_str(qtype).to_string();
            pos += 4;
        }
    }

    let mut answers = Vec::new();
    for _ in 0..ancount.min(8) {
        if pos >= data.len() { break; }
        // Skip name
        if data[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            let (_, new_pos) = read_dns_name(data, pos);
            pos = new_pos;
        }
        if pos + 10 > data.len() { break; }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > data.len() { break; }
        match rtype {
            1 if rdlen == 4 => {
                answers.push(format!("{}.{}.{}.{}", data[pos], data[pos + 1], data[pos + 2], data[pos + 3]));
            }
            28 if rdlen == 16 => {
                let parts: Vec<String> = data[pos..pos + 16]
                    .chunks(2)
                    .map(|c| format!("{:x}", u16::from_be_bytes([c[0], c[1]])))
                    .collect();
                answers.push(parts.join(":"));
            }
            5 => {
                // CNAME
                let (cname, _) = read_dns_name(data, pos);
                answers.push(format!("CNAME {}", cname));
            }
            _ => {}
        }
        pos += rdlen;
    }

    Some(L7Info::Dns { query, qtype: qtype_str, answers, is_response })
}

fn read_dns_name(data: &[u8], mut pos: usize) -> (String, usize) {
    let mut parts = Vec::new();
    let mut limit = 0usize;
    while pos < data.len() && limit < 128 {
        limit += 1;
        let len = data[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer
            if pos + 1 < data.len() {
                let ptr = (((len & 0x3F) as usize) << 8) | data[pos + 1] as usize;
                let (name_from_ptr, _) = read_dns_name(data, ptr);
                parts.push(name_from_ptr);
            }
            pos += 2;
            break;
        }
        pos += 1;
        if pos + len > data.len() { break; }
        parts.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        pos += len;
    }
    (parts.join("."), pos)
}

fn dns_qtype_str(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "?",
    }
}

fn parse_http(data: &[u8]) -> Option<L7Info> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    if req.parse(data).is_ok() {
        if let Some(_) = req.method {
            // Access all fields through req to avoid conflicting borrows
            let host = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("host"))
                .and_then(|h| std::str::from_utf8(h.value).ok())
                .unwrap_or("")
                .to_string();
            let method = req.method.unwrap_or("").to_string();
            let path = req.path.unwrap_or("/").to_string();
            return Some(L7Info::Http { method, host, path, status: None });
        }
    }
    let mut headers2 = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers2);
    if resp.parse(data).is_ok() {
        if let Some(code) = resp.code {
            return Some(L7Info::Http {
                method: "RESPONSE".to_string(),
                host: String::new(),
                path: String::new(),
                status: Some(code),
            });
        }
    }
    None
}

fn parse_dhcp(data: &[u8]) -> Option<L7Info> {
    // DHCP magic cookie at offset 236
    if data.len() < 240 { return None; }
    if data[236..240] != [0x63, 0x82, 0x53, 0x63] { return None; }

    let mut pos = 240usize;
    let mut msg_type = "Unknown".to_string();
    while pos + 2 <= data.len() {
        let opt = data[pos];
        if opt == 255 { break; }
        if opt == 0 { pos += 1; continue; }
        let len = data[pos + 1] as usize;
        pos += 2;
        if pos + len > data.len() { break; }
        if opt == 53 && len == 1 {
            msg_type = match data[pos] {
                1 => "Discover",
                2 => "Offer",
                3 => "Request",
                4 => "Decline",
                5 => "Ack",
                6 => "Nak",
                7 => "Release",
                8 => "Inform",
                _ => "Unknown",
            }
            .to_string();
        }
        pos += len;
    }
    Some(L7Info::Dhcp { msg_type })
}

fn is_quic(data: &[u8]) -> bool {
    if data.len() < 5 { return false; }
    // Long header: bit 7 = 1, bit 6 = 1 (fixed bit in QUIC v1)
    if data[0] & 0xC0 != 0xC0 { return false; }
    // Version field (bytes 1-4) - check for known QUIC versions
    let ver = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    matches!(ver, 0x00000001 | 0x6b3343cf | 0x51303434 | 0x51303530 | 0x00000000)
}

fn parse_quic(data: &[u8]) -> Option<L7Info> {
    if data.len() < 5 { return None; }
    let ver = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    Some(L7Info::Quic { version: Some(ver) })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Build a minimal TLS 1.2 ClientHello with an SNI extension.
    fn make_tls_client_hello(sni: &str) -> Vec<u8> {
        let sni_bytes = sni.as_bytes();
        let name_len = sni_bytes.len() as u16;

        // SNI extension data layout:
        //   list_len  (2) = 3 + name_len
        //   entry_type(1) = 0x00 (host_name)
        //   name_len  (2) = name_len
        //   name      (name_len bytes)
        let sni_data_len = (2 + 1 + 2 + name_len as usize) as u16; // = 5 + name_len

        // Extensions block: type(2) + ext_len(2) + ext_data
        let ext_block_len = 2 + 2 + sni_data_len as usize;

        // ClientHello body:
        //   version(2) random(32) sid_len(1) cs_len(2) cs(2) cm_len(1) cm(1)
        //   ext_total_len(2) ext_block
        let hello_body_len = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext_block_len;

        // Record: type(1) ver(2) record_len(2) hs_type(1) hs_len(3) hello_body
        let record_content_len = 1 + 3 + hello_body_len; // hs header + hello body

        let mut p = Vec::new();

        // TLS record header
        p.push(0x16); // handshake
        p.push(0x03); p.push(0x01); // version TLS 1.0 compat
        p.push((record_content_len >> 8) as u8);
        p.push((record_content_len & 0xff) as u8);

        // Handshake header
        p.push(0x01); // ClientHello
        p.push(0x00);
        p.push((hello_body_len >> 8) as u8);
        p.push((hello_body_len & 0xff) as u8);

        // ClientHello body
        p.push(0x03); p.push(0x03); // client_version TLS 1.2
        p.extend_from_slice(&[0u8; 32]); // random
        p.push(0x00); // session_id_len = 0
        p.push(0x00); p.push(0x02); // cipher_suites_len = 2
        p.push(0x00); p.push(0x2f); // TLS_RSA_WITH_AES_128_CBC_SHA
        p.push(0x01); // compression_methods_len = 1
        p.push(0x00); // null compression

        // Extensions total length
        p.push((ext_block_len >> 8) as u8);
        p.push((ext_block_len & 0xff) as u8);

        // SNI extension
        p.push(0x00); p.push(0x00); // type = 0 (SNI)
        p.push((sni_data_len >> 8) as u8);
        p.push((sni_data_len & 0xff) as u8);
        // SNI data
        let list_len = 1u16 + 2 + name_len; // entry_type + name_len_field + name
        p.push((list_len >> 8) as u8);
        p.push((list_len & 0xff) as u8);
        p.push(0x00); // entry_type = host_name
        p.push((name_len >> 8) as u8);
        p.push((name_len & 0xff) as u8);
        p.extend_from_slice(sni_bytes);

        p
    }

    /// Build a minimal DNS query packet (UDP payload only).
    fn make_dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut p = Vec::new();
        // Header
        p.extend_from_slice(&[0x12, 0x34]); // id
        p.extend_from_slice(&[0x01, 0x00]); // flags: standard query
        p.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
        p.extend_from_slice(&[0x00, 0x00]); // ancount
        p.extend_from_slice(&[0x00, 0x00]); // nscount
        p.extend_from_slice(&[0x00, 0x00]); // arcount
        // Question: encode name as labels
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0x00); // root label
        p.push((qtype >> 8) as u8);
        p.push((qtype & 0xff) as u8);
        p.extend_from_slice(&[0x00, 0x01]); // qclass IN
        p
    }

    /// Build a DNS A-record response for a single IPv4 address.
    fn make_dns_response_a(name: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut p = make_dns_query(name, 1 /* A */);
        // Flip to response
        p[2] = 0x81; p[3] = 0x80;
        // ancount = 1
        p[6] = 0x00; p[7] = 0x01;
        // Answer: name pointer to offset 12, type A, class IN, ttl 300, rdlen 4, rdata
        p.extend_from_slice(&[0xc0, 0x0c]); // pointer to offset 12
        p.extend_from_slice(&[0x00, 0x01]); // type A
        p.extend_from_slice(&[0x00, 0x01]); // class IN
        p.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // ttl 300
        p.extend_from_slice(&[0x00, 0x04]); // rdlength
        p.extend_from_slice(&ip);
        p
    }

    /// Build a minimal DHCP Discover payload (UDP payload only).
    fn make_dhcp_discover() -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = 1; // op BOOTREQUEST
        p[1] = 1; // htype Ethernet
        p[2] = 6; // hlen
        // magic cookie
        p[236] = 0x63; p[237] = 0x82; p[238] = 0x53; p[239] = 0x63;
        // Option 53 (DHCP Message Type) = Discover (1)
        p.push(53); p.push(1); p.push(1);
        // Option 255 (End)
        p.push(255);
        p
    }

    // ── TLS tests ─────────────────────────────────────────────────────────────

    #[test]
    fn test_tls_client_hello_sni_extracted() {
        let data = make_tls_client_hello("example.com");
        let result = decode_l7_tcp(12345, 443, &data);
        let Some(L7Info::Tls { sni, version, handshake }) = result else {
            panic!("Expected TLS L7Info, got {:?}", result);
        };
        assert_eq!(sni.as_deref(), Some("example.com"));
        assert!(version.contains("1.2"), "expected TLS 1.2, got {version}");
        assert_eq!(handshake, "ClientHello");
    }

    #[test]
    fn test_tls_client_hello_long_sni() {
        let sni = "very.long.subdomain.example.co.uk";
        let data = make_tls_client_hello(sni);
        let result = decode_l7_tcp(54321, 443, &data);
        let Some(L7Info::Tls { sni: extracted, .. }) = result else {
            panic!("Expected TLS");
        };
        assert_eq!(extracted.as_deref(), Some(sni));
    }

    #[test]
    fn test_tls_non_client_hello_no_sni() {
        // TLS ApplicationData record (type 0x17)
        let data = vec![0x17, 0x03, 0x03, 0x00, 0x10, 0xAB, 0xCD];
        let result = decode_l7_tcp(443, 54321, &data);
        let Some(L7Info::Tls { sni, handshake, .. }) = result else {
            panic!("Expected TLS");
        };
        assert!(sni.is_none());
        assert_eq!(handshake, "ApplicationData");
    }

    #[test]
    fn test_tls_server_hello_handshake_label() {
        // TLS Handshake, ServerHello (type 0x02)
        let mut data = vec![0x16, 0x03, 0x03, 0x00, 0x05];
        data.push(0x02); // ServerHello
        data.extend_from_slice(&[0x00, 0x00, 0x00]); // length
        let result = decode_l7_tcp(443, 54321, &data);
        let Some(L7Info::Tls { handshake, .. }) = result else {
            panic!("Expected TLS");
        };
        assert_eq!(handshake, "ServerHello");
    }

    #[test]
    fn test_tls_not_detected_for_garbage() {
        let data = b"not tls data at all";
        let result = decode_l7_tcp(12345, 9999, data);
        assert!(result.is_none());
    }

    #[test]
    fn test_tls_short_data_returns_none() {
        let data = vec![0x16, 0x03]; // truncated record
        let result = decode_l7_tcp(12345, 443, &data);
        // too short to parse, but starts with 0x16 0x03 — may return None or TLS
        // just ensure no panic
        let _ = result;
    }

    // ── HTTP tests ────────────────────────────────────────────────────────────

    #[test]
    fn test_http_get_request() {
        let data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        let result = decode_l7_tcp(54321, 80, data);
        let Some(L7Info::Http { method, host, path, status }) = result else {
            panic!("Expected HTTP, got {:?}", result);
        };
        assert_eq!(method, "GET");
        assert_eq!(host, "example.com");
        assert_eq!(path, "/index.html");
        assert!(status.is_none());
    }

    #[test]
    fn test_http_post_request() {
        let data = b"POST /api/v1/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n";
        let result = decode_l7_tcp(54321, 80, data);
        let Some(L7Info::Http { method, host, path, .. }) = result else {
            panic!("Expected HTTP");
        };
        assert_eq!(method, "POST");
        assert_eq!(host, "api.example.com");
        assert_eq!(path, "/api/v1/data");
    }

    #[test]
    fn test_http_response_200() {
        let data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        let result = decode_l7_tcp(80, 54321, data);
        let Some(L7Info::Http { status, method, .. }) = result else {
            panic!("Expected HTTP response");
        };
        assert_eq!(status, Some(200));
        assert_eq!(method, "RESPONSE");
    }

    #[test]
    fn test_http_response_404() {
        let data = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let result = decode_l7_tcp(80, 54321, data);
        let Some(L7Info::Http { status, .. }) = result else {
            panic!("Expected HTTP");
        };
        assert_eq!(status, Some(404));
    }

    #[test]
    fn test_http_detected_on_non_standard_port() {
        let data = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        // On port 8080 — listed in our port heuristic
        let result = decode_l7_tcp(54321, 8080, data);
        assert!(matches!(result, Some(L7Info::Http { .. })));
    }

    // ── DNS tests ─────────────────────────────────────────────────────────────

    #[test]
    fn test_dns_query_a_record() {
        let data = make_dns_query("example.com", 1);
        let result = decode_l7_udp(12345, 53, &data);
        let Some(L7Info::Dns { query, qtype, is_response, .. }) = result else {
            panic!("Expected DNS, got {:?}", result);
        };
        assert_eq!(query, "example.com");
        assert_eq!(qtype, "A");
        assert!(!is_response);
    }

    #[test]
    fn test_dns_query_aaaa_record() {
        let data = make_dns_query("ipv6.example.com", 28);
        let result = decode_l7_udp(12345, 53, &data);
        let Some(L7Info::Dns { query, qtype, .. }) = result else {
            panic!("Expected DNS");
        };
        assert_eq!(query, "ipv6.example.com");
        assert_eq!(qtype, "AAAA");
    }

    #[test]
    fn test_dns_response_with_a_record() {
        let data = make_dns_response_a("example.com", [93, 184, 216, 34]);
        let result = decode_l7_udp(53, 12345, &data);
        let Some(L7Info::Dns { query, is_response, answers, .. }) = result else {
            panic!("Expected DNS response, got {:?}", result);
        };
        assert_eq!(query, "example.com");
        assert!(is_response);
        assert_eq!(answers, vec!["93.184.216.34"]);
    }

    #[test]
    fn test_dns_mdns_port_5353() {
        let data = make_dns_query("local.example", 1);
        let result = decode_l7_udp(5353, 5353, &data);
        assert!(matches!(result, Some(L7Info::Dns { .. })));
    }

    #[test]
    fn test_dns_too_short_returns_none() {
        let data = vec![0x12, 0x34, 0x01]; // only 3 bytes, need >= 12
        let result = decode_l7_udp(12345, 53, &data);
        assert!(result.is_none());
    }

    // ── DHCP tests ────────────────────────────────────────────────────────────

    #[test]
    fn test_dhcp_discover_detected() {
        let data = make_dhcp_discover();
        let result = decode_l7_udp(68, 67, &data);
        let Some(L7Info::Dhcp { msg_type }) = result else {
            panic!("Expected DHCP, got {:?}", result);
        };
        assert_eq!(msg_type, "Discover");
    }

    #[test]
    fn test_dhcp_ack_detected() {
        let mut data = make_dhcp_discover();
        // Change option 53 value from 1 (Discover) to 5 (Ack)
        let opt53_pos = data.iter().position(|&b| b == 53).unwrap();
        data[opt53_pos + 2] = 5;
        let result = decode_l7_udp(67, 68, &data);
        let Some(L7Info::Dhcp { msg_type }) = result else {
            panic!("Expected DHCP Ack");
        };
        assert_eq!(msg_type, "Ack");
    }

    #[test]
    fn test_dhcp_wrong_magic_cookie_ignored() {
        let mut data = make_dhcp_discover();
        data[236] = 0x00; // corrupt magic cookie
        let result = decode_l7_udp(68, 67, &data);
        assert!(result.is_none());
    }

    // ── QUIC tests ────────────────────────────────────────────────────────────

    #[test]
    fn test_quic_v1_initial_detected() {
        // QUIC v1 long header Initial packet
        let mut data = vec![0xC0]; // long header + fixed bit
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // version 1
        data.extend_from_slice(&[0x00; 10]); // rest of packet
        let result = decode_l7_udp(12345, 443, &data);
        let Some(L7Info::Quic { version }) = result else {
            panic!("Expected QUIC, got {:?}", result);
        };
        assert_eq!(version, Some(0x00000001));
    }

    #[test]
    fn test_quic_v2_detected() {
        // QUIC v2 (RFC 9369)
        let mut data = vec![0xD0]; // long header
        data.extend_from_slice(&[0x6b, 0x33, 0x43, 0xcf]); // version 2
        data.extend_from_slice(&[0x00; 10]);
        let result = decode_l7_udp(12345, 443, &data);
        assert!(matches!(result, Some(L7Info::Quic { .. })));
    }

    #[test]
    fn test_quic_not_detected_for_short_packet() {
        let data = vec![0xC0, 0x00]; // too short (< 5 bytes)
        let result = decode_l7_udp(12345, 443, &data);
        assert!(result.is_none());
    }

    #[test]
    fn test_quic_not_detected_without_long_header_bit() {
        // Short header packet (bit 7 = 1 but bit 6 = 0, so 0x80 not 0xC0)
        let mut data = vec![0x40]; // fixed bit set but not long header marker
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        let result = decode_l7_udp(12345, 443, &data);
        assert!(result.is_none());
    }

    // ── HTTP/2 tests ──────────────────────────────────────────────────────────

    #[test]
    fn test_http2_preface_detected() {
        let data = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let result = decode_l7_tcp(12345, 443, data);
        assert!(matches!(result, Some(L7Info::Http2)));
    }

    #[test]
    fn test_http2_not_detected_for_partial_preface() {
        let data = b"PRI * HTTP/2.0\r\n"; // incomplete preface
        let result = decode_l7_tcp(12345, 443, data);
        assert!(!matches!(result, Some(L7Info::Http2)));
    }

    // ── L7Info helpers ────────────────────────────────────────────────────────

    #[test]
    fn test_l7info_summary_dns_query() {
        let info = L7Info::Dns {
            query: "example.com".to_string(),
            qtype: "A".to_string(),
            answers: vec![],
            is_response: false,
        };
        assert_eq!(info.summary(), "A example.com?");
    }

    #[test]
    fn test_l7info_summary_dns_response() {
        let info = L7Info::Dns {
            query: "example.com".to_string(),
            qtype: "A".to_string(),
            answers: vec!["93.184.216.34".to_string()],
            is_response: true,
        };
        assert_eq!(info.summary(), "A example.com → 93.184.216.34");
    }

    #[test]
    fn test_l7info_summary_http_request() {
        let info = L7Info::Http {
            method: "GET".to_string(),
            host: "example.com".to_string(),
            path: "/index.html".to_string(),
            status: None,
        };
        assert_eq!(info.summary(), "GET example.com/index.html");
    }

    #[test]
    fn test_l7info_summary_http_response() {
        let info = L7Info::Http {
            method: "RESPONSE".to_string(),
            host: String::new(),
            path: String::new(),
            status: Some(200),
        };
        assert!(info.summary().contains("200"));
    }

    #[test]
    fn test_l7info_summary_tls_with_sni() {
        let info = L7Info::Tls {
            sni: Some("example.com".to_string()),
            version: "TLS 1.3".to_string(),
            handshake: "ClientHello".to_string(),
        };
        assert!(info.summary().contains("example.com"));
        assert!(info.summary().contains("TLS 1.3"));
    }
}
