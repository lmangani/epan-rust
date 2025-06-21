// rust-pcap-dissector/src/dissector.rs
use std::fs::File;
use std::path::Path;
use pcap_file::pcap::PcapReader;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketDissection {
    pub packet_number: u32,
    pub timestamp: String,
    pub length: u32,
    pub captured_length: u32,
    pub protocols: Vec<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub info: Option<String>,
    pub fields: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PcapDissectionResult {
    pub file_info: FileInfo,
    pub packets: Vec<PacketDissection>,
    pub summary: DissectionSummary,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileInfo {
    pub filename: String,
    pub total_packets: u32,
    pub file_size: u64,
    pub capture_start_time: Option<String>,
    pub capture_end_time: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DissectionSummary {
    pub protocol_distribution: std::collections::HashMap<String, u32>,
    pub total_bytes: u64,
    pub duration_seconds: f64,
    pub packets_per_second: f64,
}

pub struct PcapDissector {
    initialized: bool,
}

impl PcapDissector {
    pub fn new() -> Result<Self, String> {
        // Skip epan initialization to avoid privilege assertion errors
        // Our enhanced manual parsing provides comprehensive protocol analysis
        println!("Initializing enhanced protocol dissector (epan disabled to avoid privilege issues)");

        Ok(PcapDissector {
            initialized: true,
        })
    }

    /// Main function to dissect a pcap file and return JSON
    pub fn dissect_pcap_to_json<P: AsRef<Path>>(pcap_path: P) -> Result<String, Box<dyn std::error::Error>> {
        let dissector = Self::new().map_err(|e| format!("Failed to initialize dissector: {}", e))?;
        let result = dissector.dissect_pcap_file(pcap_path)?;
        Ok(serde_json::to_string_pretty(&result)?)
    }

    /// Dissect a pcap file and return structured results
    pub fn dissect_pcap_file<P: AsRef<Path>>(&self, pcap_path: P) -> Result<PcapDissectionResult, Box<dyn std::error::Error>> {
        let path = pcap_path.as_ref();
        let file = File::open(path)?;
        let file_size = file.metadata()?.len();
        
        let mut pcap_reader = PcapReader::new(file)?;
        let mut packets = Vec::new();
        let mut protocol_counts = std::collections::HashMap::new();
        let mut total_bytes = 0u64;
        let mut start_time: Option<DateTime<Utc>> = None;
        let mut end_time: Option<DateTime<Utc>> = None;

        // Read and dissect each packet
        while let Some(pkt) = pcap_reader.next_packet() {
            let packet = pkt?;
            
            // Extract timestamp from the packet timestamp field
            let timestamp = DateTime::from_timestamp(
                packet.timestamp.as_secs() as i64,
                packet.timestamp.subsec_nanos(),
            ).unwrap_or_else(Utc::now);

            // Track time range
            if start_time.is_none() || timestamp < start_time.unwrap() {
                start_time = Some(timestamp);
            }
            if end_time.is_none() || timestamp > end_time.unwrap() {
                end_time = Some(timestamp);
            }

            // Use enhanced dissection
            let dissection = self.dissect_packet_enhanced(&packet.data, timestamp, packets.len() as u32 + 1);
            
            // Update statistics
            total_bytes += dissection.length as u64;
            if let Some(ref protocol) = dissection.protocol {
                *protocol_counts.entry(protocol.clone()).or_insert(0) += 1;
            }
            
            packets.push(dissection);
        }

        // Calculate summary statistics
        let duration = if let (Some(start), Some(end)) = (start_time, end_time) {
            (end - start).num_milliseconds() as f64 / 1000.0
        } else {
            0.0
        };

        let packets_per_second = if duration > 0.0 {
            packets.len() as f64 / duration
        } else {
            0.0
        };

        let result = PcapDissectionResult {
            file_info: FileInfo {
                filename: path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                total_packets: packets.len() as u32,
                file_size,
                capture_start_time: start_time.map(|t| t.to_rfc3339()),
                capture_end_time: end_time.map(|t| t.to_rfc3339()),
            },
            packets,
            summary: DissectionSummary {
                protocol_distribution: protocol_counts,
                total_bytes,
                duration_seconds: duration,
                packets_per_second,
            },
        };

        Ok(result)
    }

    // Enhanced packet dissection with deep protocol analysis
    fn dissect_packet_enhanced(&self, packet_data: &[u8], timestamp: DateTime<Utc>, packet_num: u32) -> PacketDissection {
        let mut dissection = PacketDissection {
            packet_number: packet_num,
            timestamp: timestamp.to_rfc3339(),
            length: packet_data.len() as u32,
            captured_length: packet_data.len() as u32,
            protocols: vec!["Raw".to_string()],
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            protocol: Some("Unknown".to_string()),
            info: None,
            fields: std::collections::HashMap::new(),
        };

        // Enhanced ethernet frame parsing
        if packet_data.len() >= 14 {
            dissection.protocols = vec!["Ethernet".to_string()];
            
            // Extract MAC addresses
            let dst_mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                packet_data[0], packet_data[1], packet_data[2], 
                packet_data[3], packet_data[4], packet_data[5]);
            let src_mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                packet_data[6], packet_data[7], packet_data[8], 
                packet_data[9], packet_data[10], packet_data[11]);
            
            dissection.fields.insert("eth.dst".to_string(), serde_json::Value::String(dst_mac));
            dissection.fields.insert("eth.src".to_string(), serde_json::Value::String(src_mac));
            
            // Check ethertype for IP
            if packet_data.len() > 12 {
                let ethertype = u16::from_be_bytes([packet_data[12], packet_data[13]]);
                dissection.fields.insert("eth.type".to_string(), serde_json::Value::String(format!("0x{:04x}", ethertype)));
                
                match ethertype {
                    0x0800 => {
                        dissection.protocols.push("IPv4".to_string());
                        self.parse_ipv4_enhanced(&mut dissection, &packet_data[14..]);
                    }
                    0x86DD => {
                        dissection.protocols.push("IPv6".to_string());
                        self.parse_ipv6_enhanced(&mut dissection, &packet_data[14..]);
                    }
                    0x0806 => {
                        dissection.protocol = Some("ARP".to_string());
                        self.parse_arp(&mut dissection, &packet_data[14..]);
                    }
                    _ => {
                        dissection.protocol = Some("Ethernet".to_string());
                    }
                }
            }
        }

        // Generate enhanced info string
        self.generate_info_string(&mut dissection);

        dissection
    }

    // Enhanced IPv4 parsing with detailed field extraction
    fn parse_ipv4_enhanced(&self, dissection: &mut PacketDissection, ip_data: &[u8]) {
        if ip_data.len() < 20 {
            return;
        }

        // Extract IP header fields
        let version = (ip_data[0] & 0xF0) >> 4;
        let header_len = (ip_data[0] & 0x0F) * 4;
        let dscp = (ip_data[1] & 0xFC) >> 2;
        let ecn = ip_data[1] & 0x03;
        let total_length = u16::from_be_bytes([ip_data[2], ip_data[3]]);
        let identification = u16::from_be_bytes([ip_data[4], ip_data[5]]);
        let flags = (ip_data[6] & 0xE0) >> 5;
        let fragment_offset = u16::from_be_bytes([ip_data[6], ip_data[7]]) & 0x1FFF;
        let ttl = ip_data[8];
        let protocol = ip_data[9];
        let checksum = u16::from_be_bytes([ip_data[10], ip_data[11]]);

        // Extract source and destination IPs
        dissection.src_ip = Some(format!("{}.{}.{}.{}", 
            ip_data[12], ip_data[13], ip_data[14], ip_data[15]));
        dissection.dst_ip = Some(format!("{}.{}.{}.{}", 
            ip_data[16], ip_data[17], ip_data[18], ip_data[19]));

        // Add IPv4 fields
        dissection.fields.insert("ip.version".to_string(), serde_json::Value::Number(version.into()));
        dissection.fields.insert("ip.hdr_len".to_string(), serde_json::Value::Number(header_len.into()));
        dissection.fields.insert("ip.dscp".to_string(), serde_json::Value::Number(dscp.into()));
        dissection.fields.insert("ip.ecn".to_string(), serde_json::Value::Number(ecn.into()));
        dissection.fields.insert("ip.len".to_string(), serde_json::Value::Number(total_length.into()));
        dissection.fields.insert("ip.id".to_string(), serde_json::Value::Number(identification.into()));
        dissection.fields.insert("ip.flags".to_string(), serde_json::Value::Number(flags.into()));
        dissection.fields.insert("ip.frag_offset".to_string(), serde_json::Value::Number(fragment_offset.into()));
        dissection.fields.insert("ip.ttl".to_string(), serde_json::Value::Number(ttl.into()));
        dissection.fields.insert("ip.proto".to_string(), serde_json::Value::Number(protocol.into()));
        dissection.fields.insert("ip.checksum".to_string(), serde_json::Value::String(format!("0x{:04x}", checksum)));
        dissection.fields.insert("ip.src".to_string(), serde_json::Value::String(dissection.src_ip.as_ref().unwrap().clone()));
        dissection.fields.insert("ip.dst".to_string(), serde_json::Value::String(dissection.dst_ip.as_ref().unwrap().clone()));

        // Parse transport layer
        let header_len = header_len as usize;
        if ip_data.len() > header_len {
            match protocol {
                6 => self.parse_tcp_enhanced(dissection, &ip_data[header_len..]),
                17 => self.parse_udp_enhanced(dissection, &ip_data[header_len..]),
                1 => self.parse_icmp_enhanced(dissection, &ip_data[header_len..]),
                _ => {
                    dissection.protocol = Some("IPv4".to_string());
                }
            }
        }
    }

    // Enhanced IPv6 parsing
    fn parse_ipv6_enhanced(&self, dissection: &mut PacketDissection, ipv6_data: &[u8]) {
        if ipv6_data.len() < 40 {
            return;
        }

        // Extract IPv6 addresses
        let src_bytes = &ipv6_data[8..24];
        let dst_bytes = &ipv6_data[24..40];
        
        dissection.src_ip = Some(format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3],
            src_bytes[4], src_bytes[5], src_bytes[6], src_bytes[7],
            src_bytes[8], src_bytes[9], src_bytes[10], src_bytes[11],
            src_bytes[12], src_bytes[13], src_bytes[14], src_bytes[15]));
        
        dissection.dst_ip = Some(format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            dst_bytes[0], dst_bytes[1], dst_bytes[2], dst_bytes[3],
            dst_bytes[4], dst_bytes[5], dst_bytes[6], dst_bytes[7],
            dst_bytes[8], dst_bytes[9], dst_bytes[10], dst_bytes[11],
            dst_bytes[12], dst_bytes[13], dst_bytes[14], dst_bytes[15]));

        let next_header = ipv6_data[6];
        dissection.fields.insert("ipv6.nxt".to_string(), serde_json::Value::Number(next_header.into()));
        dissection.fields.insert("ipv6.src".to_string(), serde_json::Value::String(dissection.src_ip.as_ref().unwrap().clone()));
        dissection.fields.insert("ipv6.dst".to_string(), serde_json::Value::String(dissection.dst_ip.as_ref().unwrap().clone()));

        dissection.protocol = Some("IPv6".to_string());
    }

    // Enhanced TCP parsing with detailed field extraction
    fn parse_tcp_enhanced(&self, dissection: &mut PacketDissection, tcp_data: &[u8]) {
        if tcp_data.len() < 20 {
            return;
        }

        dissection.protocols.push("TCP".to_string());
        
        // Extract TCP header fields
        let src_port = u16::from_be_bytes([tcp_data[0], tcp_data[1]]);
        let dst_port = u16::from_be_bytes([tcp_data[2], tcp_data[3]]);
        let seq_num = u32::from_be_bytes([tcp_data[4], tcp_data[5], tcp_data[6], tcp_data[7]]);
        let ack_num = u32::from_be_bytes([tcp_data[8], tcp_data[9], tcp_data[10], tcp_data[11]]);
        let header_len = ((tcp_data[12] & 0xF0) >> 4) * 4;
        let flags = tcp_data[13];
        let window_size = u16::from_be_bytes([tcp_data[14], tcp_data[15]]);
        let checksum = u16::from_be_bytes([tcp_data[16], tcp_data[17]]);
        let urgent_ptr = u16::from_be_bytes([tcp_data[18], tcp_data[19]]);

        dissection.src_port = Some(src_port);
        dissection.dst_port = Some(dst_port);

        // Add TCP fields
        dissection.fields.insert("tcp.srcport".to_string(), serde_json::Value::Number(src_port.into()));
        dissection.fields.insert("tcp.dstport".to_string(), serde_json::Value::Number(dst_port.into()));
        dissection.fields.insert("tcp.seq".to_string(), serde_json::Value::Number(seq_num.into()));
        dissection.fields.insert("tcp.ack".to_string(), serde_json::Value::Number(ack_num.into()));
        dissection.fields.insert("tcp.hdr_len".to_string(), serde_json::Value::Number(header_len.into()));
        dissection.fields.insert("tcp.flags".to_string(), serde_json::Value::Number(flags.into()));
        dissection.fields.insert("tcp.window_size".to_string(), serde_json::Value::Number(window_size.into()));
        dissection.fields.insert("tcp.checksum".to_string(), serde_json::Value::String(format!("0x{:04x}", checksum)));
        dissection.fields.insert("tcp.urgent_ptr".to_string(), serde_json::Value::Number(urgent_ptr.into()));
        
        // TCP flag analysis
        dissection.fields.insert("tcp.flags.fin".to_string(), serde_json::Value::Bool((flags & 0x01) != 0));
        dissection.fields.insert("tcp.flags.syn".to_string(), serde_json::Value::Bool((flags & 0x02) != 0));
        dissection.fields.insert("tcp.flags.rst".to_string(), serde_json::Value::Bool((flags & 0x04) != 0));
        dissection.fields.insert("tcp.flags.psh".to_string(), serde_json::Value::Bool((flags & 0x08) != 0));
        dissection.fields.insert("tcp.flags.ack".to_string(), serde_json::Value::Bool((flags & 0x10) != 0));
        dissection.fields.insert("tcp.flags.urg".to_string(), serde_json::Value::Bool((flags & 0x20) != 0));

        // Detect application protocols and parse payload
        if tcp_data.len() > header_len as usize {
            let payload = &tcp_data[header_len as usize..];
            match (src_port, dst_port) {
                (80, _) | (_, 80) => {
                    self.parse_http(dissection, payload, dst_port == 80);
                    // Debug: Add payload size info and previews
                    dissection.fields.insert("http.payload_length".to_string(), serde_json::Value::Number(payload.len().into()));
                    if payload.len() > 0 {
                        // Show hex preview for debugging
                        let hex_preview = payload.iter().take(50).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                        dissection.fields.insert("http.payload_hex".to_string(), serde_json::Value::String(hex_preview));
                        
                        // Also show readable text preview
                        let text_preview = payload.iter().take(100)
                            .map(|&b| if b >= 32 && b <= 126 { b as char } else if b == 10 { '\\' } else if b == 13 { '\\' } else { '.' })
                            .collect::<String>()
                            .replace("\\", "\\n");
                        dissection.fields.insert("http.payload_text".to_string(), serde_json::Value::String(text_preview));
                    }
                }
                (443, _) | (_, 443) => {
                    dissection.protocols.push("TLS".to_string());
                    dissection.protocol = Some("HTTPS".to_string());
                }
                (22, _) | (_, 22) => dissection.protocol = Some("SSH".to_string()),
                (21, _) | (_, 21) => dissection.protocol = Some("FTP".to_string()),
                (25, _) | (_, 25) => dissection.protocol = Some("SMTP".to_string()),
                (110, _) | (_, 110) => dissection.protocol = Some("POP3".to_string()),
                (143, _) | (_, 143) => dissection.protocol = Some("IMAP".to_string()),
                (3868, _) | (_, 3868) => {
                    dissection.protocols.push("Diameter".to_string());
                    dissection.protocol = Some("Diameter".to_string());
                    self.parse_diameter(dissection, payload);
                }
                _ => dissection.protocol = Some("TCP".to_string()),
            }
        } else {
            dissection.protocol = Some("TCP".to_string());
        }
    }

    // Enhanced UDP parsing with detailed field extraction
    fn parse_udp_enhanced(&self, dissection: &mut PacketDissection, udp_data: &[u8]) {
        if udp_data.len() < 8 {
            return;
        }

        dissection.protocols.push("UDP".to_string());
        
        let src_port = u16::from_be_bytes([udp_data[0], udp_data[1]]);
        let dst_port = u16::from_be_bytes([udp_data[2], udp_data[3]]);
        let length = u16::from_be_bytes([udp_data[4], udp_data[5]]);
        let checksum = u16::from_be_bytes([udp_data[6], udp_data[7]]);

        dissection.src_port = Some(src_port);
        dissection.dst_port = Some(dst_port);

        // Add UDP fields
        dissection.fields.insert("udp.srcport".to_string(), serde_json::Value::Number(src_port.into()));
        dissection.fields.insert("udp.dstport".to_string(), serde_json::Value::Number(dst_port.into()));
        dissection.fields.insert("udp.length".to_string(), serde_json::Value::Number(length.into()));
        dissection.fields.insert("udp.checksum".to_string(), serde_json::Value::String(format!("0x{:04x}", checksum)));

        // Parse UDP payload for application protocols
        if udp_data.len() > 8 {
            let payload = &udp_data[8..];
            match (src_port, dst_port) {
                (53, _) | (_, 53) => self.parse_dns(dissection, payload, dst_port == 53),
                (67, _) | (_, 67) | (68, _) | (_, 68) => {
                    dissection.protocols.push("DHCP".to_string());
                    dissection.protocol = Some("DHCP".to_string());
                }
                (5060, _) | (_, 5060) => self.parse_sip(dissection, payload),
                (123, _) | (_, 123) => {
                    dissection.protocols.push("NTP".to_string());
                    dissection.protocol = Some("NTP".to_string());
                }
                _ if src_port > 16384 && dst_port > 16384 => {
                    // Potential RTP
                    if self.is_rtp_packet(payload) {
                        self.parse_rtp(dissection, payload);
                    } else {
                        dissection.protocol = Some("UDP".to_string());
                    }
                }
                _ => dissection.protocol = Some("UDP".to_string()),
            }
        } else {
            dissection.protocol = Some("UDP".to_string());
        }
    }

    // Parse DNS packets with detailed field extraction
    fn parse_dns(&self, dissection: &mut PacketDissection, dns_data: &[u8], _is_query: bool) {
        if dns_data.len() < 12 {
            return;
        }

        dissection.protocols.push("DNS".to_string());
        dissection.protocol = Some("DNS".to_string());

        // Parse DNS header
        let transaction_id = u16::from_be_bytes([dns_data[0], dns_data[1]]);
        let flags = u16::from_be_bytes([dns_data[2], dns_data[3]]);
        let questions = u16::from_be_bytes([dns_data[4], dns_data[5]]);
        let answers = u16::from_be_bytes([dns_data[6], dns_data[7]]);
        let authority = u16::from_be_bytes([dns_data[8], dns_data[9]]);
        let additional = u16::from_be_bytes([dns_data[10], dns_data[11]]);

        let qr = (flags & 0x8000) != 0;
        let opcode = (flags & 0x7800) >> 11;
        let aa = (flags & 0x0400) != 0;
        let tc = (flags & 0x0200) != 0;
        let rd = (flags & 0x0100) != 0;
        let ra = (flags & 0x0080) != 0;
        let rcode = flags & 0x000F;

        // Add DNS fields
        dissection.fields.insert("dns.id".to_string(), serde_json::Value::Number(transaction_id.into()));
        dissection.fields.insert("dns.flags".to_string(), serde_json::Value::String(format!("0x{:04x}", flags)));
        dissection.fields.insert("dns.qr".to_string(), serde_json::Value::Bool(qr));
        dissection.fields.insert("dns.opcode".to_string(), serde_json::Value::Number(opcode.into()));
        dissection.fields.insert("dns.aa".to_string(), serde_json::Value::Bool(aa));
        dissection.fields.insert("dns.tc".to_string(), serde_json::Value::Bool(tc));
        dissection.fields.insert("dns.rd".to_string(), serde_json::Value::Bool(rd));
        dissection.fields.insert("dns.ra".to_string(), serde_json::Value::Bool(ra));
        dissection.fields.insert("dns.rcode".to_string(), serde_json::Value::Number(rcode.into()));
        dissection.fields.insert("dns.questions".to_string(), serde_json::Value::Number(questions.into()));
        dissection.fields.insert("dns.answers".to_string(), serde_json::Value::Number(answers.into()));
        dissection.fields.insert("dns.authority".to_string(), serde_json::Value::Number(authority.into()));
        dissection.fields.insert("dns.additional".to_string(), serde_json::Value::Number(additional.into()));
        dissection.fields.insert("dns.query".to_string(), serde_json::Value::Bool(!qr));
        dissection.fields.insert("dns.response".to_string(), serde_json::Value::Bool(qr));

        // Try to extract query name (simplified)
        if questions > 0 && dns_data.len() > 12 {
            if let Some(query_name) = self.extract_dns_name(&dns_data[12..]) {
                dissection.fields.insert("dns.qry.name".to_string(), serde_json::Value::String(query_name));
            }
        }
    }

    // Parse HTTP packets with enhanced content extraction
    fn parse_http(&self, dissection: &mut PacketDissection, http_data: &[u8], is_request: bool) {
        dissection.protocols.push("HTTP".to_string());
        dissection.protocol = Some("HTTP".to_string());
        
        // First, try to convert to UTF-8, but handle binary data gracefully
        let mut http_content = String::new();
        let mut valid_text = true;
        
        match std::str::from_utf8(http_data) {
            Ok(text) => {
                http_content = text.to_string();
            }
            Err(_) => {
                // Try to extract printable ASCII characters
                valid_text = false;
                for &byte in http_data.iter().take(2048) { // Limit to first 2KB
                    if byte >= 32 && byte <= 126 || byte == 10 || byte == 13 {
                        http_content.push(byte as char);
                    } else if byte == 0 {
                        break; // Stop at null byte
                    } else {
                        http_content.push('.');
                    }
                }
            }
        }

        if http_content.is_empty() {
            // No readable content, add binary info
            dissection.fields.insert("http.binary_data".to_string(), serde_json::Value::Bool(true));
            dissection.fields.insert("http.data_length".to_string(), serde_json::Value::Number(http_data.len().into()));
            return;
        }

        // Add raw content length
        dissection.fields.insert("http.content_length".to_string(), serde_json::Value::Number(http_data.len().into()));
        dissection.fields.insert("http.text_data".to_string(), serde_json::Value::Bool(valid_text));
        
        // Parse HTTP content
        let lines: Vec<&str> = http_content.lines().collect();
        if lines.is_empty() {
            return;
        }

        let first_line = lines[0];
        dissection.fields.insert("http.first_line".to_string(), serde_json::Value::String(first_line.to_string()));
        
        if is_request {
            // Parse HTTP request line (e.g., "GET /path HTTP/1.1")
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 3 {
                dissection.fields.insert("http.request".to_string(), serde_json::Value::Bool(true));
                dissection.fields.insert("http.method".to_string(), serde_json::Value::String(parts[0].to_string()));
                dissection.fields.insert("http.uri".to_string(), serde_json::Value::String(parts[1].to_string()));
                dissection.fields.insert("http.version".to_string(), serde_json::Value::String(parts[2].to_string()));
            }
        } else {
            // Parse HTTP response line (e.g., "HTTP/1.1 200 OK")
            if first_line.starts_with("HTTP/") {
                let parts: Vec<&str> = first_line.split_whitespace().collect();
                if parts.len() >= 3 {
                    dissection.fields.insert("http.response".to_string(), serde_json::Value::Bool(true));
                    dissection.fields.insert("http.version".to_string(), serde_json::Value::String(parts[0].to_string()));
                    dissection.fields.insert("http.status_code".to_string(), serde_json::Value::String(parts[1].to_string()));
                    if parts.len() > 2 {
                        dissection.fields.insert("http.reason_phrase".to_string(), serde_json::Value::String(parts[2..].join(" ")));
                    }
                }
            } else {
                // Might be HTTP response body or continuation
                dissection.fields.insert("http.body_or_continuation".to_string(), serde_json::Value::Bool(true));
            }
        }

        // Parse HTTP headers
        let mut header_count = 0;
        let mut content_type = None;
        let mut content_length = None;
        
        for line in lines.iter().skip(1) {
            if line.trim().is_empty() {
                break; // End of headers
            }
            if let Some(colon_pos) = line.find(':') {
                let header_name = line[..colon_pos].trim().to_lowercase();
                let header_value = line[colon_pos + 1..].trim();
                
                // Store header with http.header. prefix
                dissection.fields.insert(
                    format!("http.header.{}", header_name.replace('-', "_")), 
                    serde_json::Value::String(header_value.to_string())
                );
                
                // Track special headers
                match header_name.as_str() {
                    "content-type" => content_type = Some(header_value.to_string()),
                    "content-length" => content_length = Some(header_value.to_string()),
                    "host" => { dissection.fields.insert("http.host".to_string(), serde_json::Value::String(header_value.to_string())); },
                    "user-agent" => { dissection.fields.insert("http.user_agent".to_string(), serde_json::Value::String(header_value.to_string())); },
                    "accept" => { dissection.fields.insert("http.accept".to_string(), serde_json::Value::String(header_value.to_string())); },
                    "cookie" => { dissection.fields.insert("http.cookie".to_string(), serde_json::Value::String(header_value.to_string())); },
                    "authorization" => { dissection.fields.insert("http.authorization".to_string(), serde_json::Value::String("***".to_string())); }, // Redact auth
                    _ => {}
                };
                
                header_count += 1;
            }
        }
        
        dissection.fields.insert("http.header_count".to_string(), serde_json::Value::Number(header_count.into()));
        
        if let Some(ct) = content_type {
            dissection.fields.insert("http.content_type".to_string(), serde_json::Value::String(ct));
        }
        
        if let Some(cl) = content_length {
            dissection.fields.insert("http.content_length_header".to_string(), serde_json::Value::String(cl));
        }

        // Find body content after headers
        let mut body_start = None;
        for (i, line) in lines.iter().enumerate() {
            if line.trim().is_empty() {
                body_start = Some(i + 1);
                break;
            }
        }
        
        if let Some(body_idx) = body_start {
            if body_idx < lines.len() {
                let body_lines = &lines[body_idx..];
                if !body_lines.is_empty() {
                    let body_preview = body_lines.iter().take(3).map(|s| s.to_string()).collect::<Vec<_>>().join("\\n");
                    dissection.fields.insert("http.body_preview".to_string(), serde_json::Value::String(body_preview));
                    dissection.fields.insert("http.body_lines".to_string(), serde_json::Value::Number(body_lines.len().into()));
                }
            }
        }

        // Add total line count for debugging
        dissection.fields.insert("http.total_lines".to_string(), serde_json::Value::Number(lines.len().into()));
    }

    // Parse SIP packets
    fn parse_sip(&self, dissection: &mut PacketDissection, sip_data: &[u8]) {
        dissection.protocols.push("SIP".to_string());
        dissection.protocol = Some("SIP".to_string());
        
        if let Ok(sip_text) = std::str::from_utf8(sip_data) {
            let lines: Vec<&str> = sip_text.lines().collect();
            if !lines.is_empty() {
                let first_line = lines[0];
                
                if first_line.starts_with("SIP/2.0") {
                    // SIP response
                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        dissection.fields.insert("sip.status_code".to_string(), serde_json::Value::String(parts[1].to_string()));
                    }
                } else {
                    // SIP request
                    let parts: Vec<&str> = first_line.split_whitespace().collect();
                    if !parts.is_empty() {
                        dissection.fields.insert("sip.method".to_string(), serde_json::Value::String(parts[0].to_string()));
                    }
                }
            }
        }
    }

    // Parse basic Diameter packets
    fn parse_diameter(&self, dissection: &mut PacketDissection, diameter_data: &[u8]) {
        if diameter_data.len() < 20 {
            return;
        }

        // Basic Diameter header parsing
        let version = diameter_data[0];
        let length = u32::from_be_bytes([0, diameter_data[1], diameter_data[2], diameter_data[3]]);
        let command_code = u32::from_be_bytes([0, diameter_data[5], diameter_data[6], diameter_data[7]]);
        
        dissection.fields.insert("diameter.version".to_string(), serde_json::Value::Number(version.into()));
        dissection.fields.insert("diameter.length".to_string(), serde_json::Value::Number(length.into()));
        dissection.fields.insert("diameter.cmd_code".to_string(), serde_json::Value::Number(command_code.into()));
    }

    // Check if packet looks like RTP
    fn is_rtp_packet(&self, payload: &[u8]) -> bool {
        if payload.len() < 12 {
            return false;
        }
        
        let version = (payload[0] & 0xC0) >> 6;
        version == 2 // RTP version 2
    }

    // Parse RTP packets
    fn parse_rtp(&self, dissection: &mut PacketDissection, rtp_data: &[u8]) {
        if rtp_data.len() < 12 {
            return;
        }

        dissection.protocols.push("RTP".to_string());
        dissection.protocol = Some("RTP".to_string());

        let version = (rtp_data[0] & 0xC0) >> 6;
        let padding = (rtp_data[0] & 0x20) != 0;
        let extension = (rtp_data[0] & 0x10) != 0;
        let cc = rtp_data[0] & 0x0F;
        let marker = (rtp_data[1] & 0x80) != 0;
        let payload_type = rtp_data[1] & 0x7F;
        let sequence_number = u16::from_be_bytes([rtp_data[2], rtp_data[3]]);
        let timestamp = u32::from_be_bytes([rtp_data[4], rtp_data[5], rtp_data[6], rtp_data[7]]);
        let ssrc = u32::from_be_bytes([rtp_data[8], rtp_data[9], rtp_data[10], rtp_data[11]]);

        dissection.fields.insert("rtp.version".to_string(), serde_json::Value::Number(version.into()));
        dissection.fields.insert("rtp.padding".to_string(), serde_json::Value::Bool(padding));
        dissection.fields.insert("rtp.extension".to_string(), serde_json::Value::Bool(extension));
        dissection.fields.insert("rtp.cc".to_string(), serde_json::Value::Number(cc.into()));
        dissection.fields.insert("rtp.marker".to_string(), serde_json::Value::Bool(marker));
        dissection.fields.insert("rtp.payload_type".to_string(), serde_json::Value::Number(payload_type.into()));
        dissection.fields.insert("rtp.seq".to_string(), serde_json::Value::Number(sequence_number.into()));
        dissection.fields.insert("rtp.timestamp".to_string(), serde_json::Value::Number(timestamp.into()));
        dissection.fields.insert("rtp.ssrc".to_string(), serde_json::Value::String(format!("0x{:08x}", ssrc)));
    }

    // Parse ICMP packets
    fn parse_icmp_enhanced(&self, dissection: &mut PacketDissection, icmp_data: &[u8]) {
        if icmp_data.len() < 8 {
            return;
        }

        dissection.protocols.push("ICMP".to_string());
        dissection.protocol = Some("ICMP".to_string());

        let icmp_type = icmp_data[0];
        let icmp_code = icmp_data[1];
        let checksum = u16::from_be_bytes([icmp_data[2], icmp_data[3]]);

        dissection.fields.insert("icmp.type".to_string(), serde_json::Value::Number(icmp_type.into()));
        dissection.fields.insert("icmp.code".to_string(), serde_json::Value::Number(icmp_code.into()));
        dissection.fields.insert("icmp.checksum".to_string(), serde_json::Value::String(format!("0x{:04x}", checksum)));
    }

    // Parse ARP packets
    fn parse_arp(&self, dissection: &mut PacketDissection, arp_data: &[u8]) {
        if arp_data.len() < 28 {
            return;
        }

        let hardware_type = u16::from_be_bytes([arp_data[0], arp_data[1]]);
        let protocol_type = u16::from_be_bytes([arp_data[2], arp_data[3]]);
        let opcode = u16::from_be_bytes([arp_data[6], arp_data[7]]);

        dissection.fields.insert("arp.hw_type".to_string(), serde_json::Value::Number(hardware_type.into()));
        dissection.fields.insert("arp.proto_type".to_string(), serde_json::Value::String(format!("0x{:04x}", protocol_type)));
        dissection.fields.insert("arp.opcode".to_string(), serde_json::Value::Number(opcode.into()));

        // Extract IP addresses from ARP
        if arp_data.len() >= 28 {
            let sender_ip = format!("{}.{}.{}.{}", arp_data[14], arp_data[15], arp_data[16], arp_data[17]);
            let target_ip = format!("{}.{}.{}.{}", arp_data[24], arp_data[25], arp_data[26], arp_data[27]);
            
            dissection.fields.insert("arp.src_proto_ipv4".to_string(), serde_json::Value::String(sender_ip));
            dissection.fields.insert("arp.dst_proto_ipv4".to_string(), serde_json::Value::String(target_ip));
        }
    }

    // Extract DNS name (simplified implementation)
    fn extract_dns_name(&self, data: &[u8]) -> Option<String> {
        let mut name = String::new();
        let mut pos = 0;
        
        while pos < data.len() {
            let len = data[pos] as usize;
            if len == 0 {
                break;
            }
            if len > 63 {
                break; // Compressed name, not handled in this simple implementation
            }
            
            pos += 1;
            if pos + len > data.len() {
                break;
            }
            
            if !name.is_empty() {
                name.push('.');
            }
            
            if let Ok(label) = std::str::from_utf8(&data[pos..pos + len]) {
                name.push_str(label);
            } else {
                break;
            }
            
            pos += len;
        }
        
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    // Generate comprehensive info string
    fn generate_info_string(&self, dissection: &mut PacketDissection) {
        if let (Some(ref src_ip), Some(ref dst_ip)) = (&dissection.src_ip, &dissection.dst_ip) {
            let protocol = dissection.protocol.as_ref().map(|s| s.as_str()).unwrap_or("Unknown");
            
            if let (Some(src_port), Some(dst_port)) = (dissection.src_port, dissection.dst_port) {
                dissection.info = Some(format!("{} {}:{} → {}:{}", 
                    protocol, src_ip, src_port, dst_ip, dst_port));
            } else {
                dissection.info = Some(format!("{} {} → {}", 
                    protocol, src_ip, dst_ip));
            }
        }
    }
}

impl Drop for PcapDissector {
    fn drop(&mut self) {
        // epan cleanup not needed since we're not initializing epan
        self.initialized = false;
    }
}
