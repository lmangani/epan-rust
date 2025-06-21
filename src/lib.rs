// rust-pcap-dissector/src/lib.rs
use std::path::Path;

mod dissector;
pub use dissector::*;

mod packet_capture;
pub use packet_capture::*;

/// Simple function to dissect a pcap file and return JSON
pub fn dissect_pcap_to_json<P: AsRef<Path>>(pcap_path: P) -> Result<String, Box<dyn std::error::Error>> {
    PcapDissector::dissect_pcap_to_json(pcap_path)
}

/// Function to dissect a pcap file and return structured data
pub fn dissect_pcap<P: AsRef<Path>>(pcap_path: P) -> Result<PcapDissectionResult, Box<dyn std::error::Error>> {
    let dissector = PcapDissector::new().map_err(|e| format!("Failed to initialize dissector: {}", e))?;
    dissector.dissect_pcap_file(pcap_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_dissector_creation() {
        let result = PcapDissector::new();
        assert!(result.is_ok(), "Failed to create dissector: {:?}", result.err());
    }

    #[test]
    fn test_pcap_dissection_api() {
        // This test would require a valid pcap file
        // For now, just test that the API is callable
        let result = dissect_pcap_to_json("nonexistent.pcap");
        assert!(result.is_err()); // Should fail because file doesn't exist
    }

    #[test]
    fn test_json_serialization() {
        let dissection = PacketDissection {
            packet_number: 1,
            timestamp: "2023-01-01T00:00:00Z".to_string(),
            length: 64,
            captured_length: 64,
            protocols: vec!["Ethernet".to_string(), "IPv4".to_string(), "TCP".to_string()],
            src_ip: Some("192.168.1.1".to_string()),
            dst_ip: Some("192.168.1.2".to_string()),
            src_port: Some(12345),
            dst_port: Some(80),
            protocol: Some("HTTP".to_string()),
            info: Some("HTTP 192.168.1.1:12345 → 192.168.1.2:80".to_string()),
            fields: std::collections::HashMap::new(),
        };

        let json = serde_json::to_string(&dissection);
        assert!(json.is_ok());
    }
}
