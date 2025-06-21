// rust-pcap-dissector/src/packet_capture.rs
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolStatistics {
    pub protocol_counts: HashMap<String, u64>,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub duration_seconds: f64,
    pub avg_packet_size: f64,
    pub packets_per_second: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowStatistics {
    pub flow_id: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

// Additional packet capture utilities can go here
