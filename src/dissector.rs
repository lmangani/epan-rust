// rust-pcap-dissector/src/dissector.rs
use epan_sys::*;
use libc::{c_void, c_char};
use std::ptr;
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

// This is the correct function signature expected by epan_init
unsafe extern "C" fn register_all_protocols(_flags: u32, _name: *const c_char, _client_data: *mut c_void) {
    // Protocol registration would happen here
    // For now, we rely on the default protocols loaded by epan_init
}

impl PcapDissector {
    pub fn new() -> Result<Self, String> {
        // For now, skip epan initialization to avoid the privilege assertion error
        // We'll implement basic packet parsing without epan, then add epan back later
        
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
            // packet.timestamp is a Duration since Unix epoch
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

            // For now, create a basic dissection without using the complex epan FFI
            // We'll add the actual epan dissection later once basic structure works
            let dissection = self.create_basic_dissection(&packet.data, timestamp, packets.len() as u32 + 1);
            
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

    // Simplified packet analysis that doesn't use epan FFI yet
    // This will get us to a working state, then we can add epan dissection
    fn create_basic_dissection(&self, packet_data: &[u8], timestamp: DateTime<Utc>, packet_num: u32) -> PacketDissection {
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

        // Basic ethernet frame parsing (without epan for now)
        if packet_data.len() >= 14 {
            dissection.protocols = vec!["Ethernet".to_string()];
            
            // Check ethertype for IP
            if packet_data.len() > 12 {
                let ethertype = u16::from_be_bytes([packet_data[12], packet_data[13]]);
                match ethertype {
                    0x0800 => {
                        dissection.protocols.push("IPv4".to_string());
                        self.parse_ipv4(&mut dissection, &packet_data[14..]);
                    }
                    0x86DD => {
                        dissection.protocols.push("IPv6".to_string());
                        dissection.protocol = Some("IPv6".to_string());
                    }
                    0x0806 => {
                        dissection.protocol = Some("ARP".to_string());
                    }
                    _ => {
                        dissection.protocol = Some("Ethernet".to_string());
                    }
                }
            }
        }

        dissection
    }

    // Basic IPv4 parsing without epan
    fn parse_ipv4(&self, dissection: &mut PacketDissection, ip_data: &[u8]) {
        if ip_data.len() < 20 {
            return;
        }

        // Extract source and destination IPs
        dissection.src_ip = Some(format!("{}.{}.{}.{}", 
            ip_data[12], ip_data[13], ip_data[14], ip_data[15]));
        dissection.dst_ip = Some(format!("{}.{}.{}.{}", 
            ip_data[16], ip_data[17], ip_data[18], ip_data[19]));

        // Check protocol
        let protocol = ip_data[9];
        let header_len = ((ip_data[0] & 0x0F) * 4) as usize;
        
        match protocol {
            6 => {
                dissection.protocols.push("TCP".to_string());
                dissection.protocol = Some("TCP".to_string());
                if ip_data.len() > header_len + 4 {
                    let tcp_data = &ip_data[header_len..];
                    dissection.src_port = Some(u16::from_be_bytes([tcp_data[0], tcp_data[1]]));
                    dissection.dst_port = Some(u16::from_be_bytes([tcp_data[2], tcp_data[3]]));
                    
                    // Detect application protocols
                    if let (Some(src), Some(dst)) = (dissection.src_port, dissection.dst_port) {
                        match (src, dst) {
                            (80, _) | (_, 80) => dissection.protocol = Some("HTTP".to_string()),
                            (443, _) | (_, 443) => dissection.protocol = Some("HTTPS".to_string()),
                            (22, _) | (_, 22) => dissection.protocol = Some("SSH".to_string()),
                            (21, _) | (_, 21) => dissection.protocol = Some("FTP".to_string()),
                            _ => {}
                        }
                    }
                }
            }
            17 => {
                dissection.protocols.push("UDP".to_string());
                dissection.protocol = Some("UDP".to_string());
                if ip_data.len() > header_len + 4 {
                    let udp_data = &ip_data[header_len..];
                    dissection.src_port = Some(u16::from_be_bytes([udp_data[0], udp_data[1]]));
                    dissection.dst_port = Some(u16::from_be_bytes([udp_data[2], udp_data[3]]));
                    
                    // Detect application protocols
                    if let (Some(src), Some(dst)) = (dissection.src_port, dissection.dst_port) {
                        match (src, dst) {
                            (53, _) | (_, 53) => dissection.protocol = Some("DNS".to_string()),
                            (67, _) | (_, 67) | (68, _) | (_, 68) => dissection.protocol = Some("DHCP".to_string()),
                            _ => {}
                        }
                    }
                }
            }
            1 => {
                dissection.protocols.push("ICMP".to_string());
                dissection.protocol = Some("ICMP".to_string());
            }
            _ => {
                dissection.protocol = Some("IPv4".to_string());
            }
        }

        // Generate info string
        if let (Some(ref src_ip), Some(ref dst_ip)) = (&dissection.src_ip, &dissection.dst_ip) {
            dissection.info = Some(format!("{} {} → {}", 
                dissection.protocol.as_ref().unwrap_or(&"Unknown".to_string()),
                src_ip, dst_ip));
        }
    }
}

impl Drop for PcapDissector {
    fn drop(&mut self) {
        if self.initialized {
            // Skip epan_cleanup for now since we're not initializing epan
            // unsafe {
            //     epan_cleanup();
            // }
            self.initialized = false;
        }
    }
}
