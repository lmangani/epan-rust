// rust-pcap-dissector/examples/basic_usage.rs
use pcap_dissector::{dissect_pcap_to_json, dissect_pcap};
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: {} <pcap_file> [options]", args[0]);
        println!("Options:");
        println!("  --json-only    Only output JSON");
        println!("  --summary      Show summary statistics only");
        return Ok(());
    }

    let pcap_file = &args[1];
    let json_only = args.contains(&"--json-only".to_string());
    let summary_only = args.contains(&"--summary".to_string());

    if json_only {
        // Simple JSON output
        let json = dissect_pcap_to_json(pcap_file)?;
        println!("{}", json);
    } else if summary_only {
        // Just show summary statistics
        let result = dissect_pcap(pcap_file)?;
        
        println!("=== PCAP File Summary ===");
        println!("File: {}", result.file_info.filename);
        println!("Total packets: {}", result.file_info.total_packets);
        println!("File size: {} bytes", result.file_info.file_size);
        println!("Total bytes: {}", result.summary.total_bytes);
        println!("Duration: {:.2} seconds", result.summary.duration_seconds);
        println!("Packets/sec: {:.2}", result.summary.packets_per_second);
        
        println!("\n=== Protocol Distribution ===");
        let mut protocols: Vec<_> = result.summary.protocol_distribution.iter().collect();
        protocols.sort_by(|a, b| b.1.cmp(a.1));
        
        for (protocol, count) in protocols.iter().take(10) {
            let percentage = **count as f64 / result.file_info.total_packets as f64 * 100.0;
            println!("{:12}: {:6} packets ({:5.1}%)", protocol, count, percentage);
        }
    } else {
        // Full analysis with pretty output
        let result = dissect_pcap(pcap_file)?;
        
        println!("=== PCAP Analysis Results ===");
        println!("File: {}", result.file_info.filename);
        println!("Packets: {}", result.file_info.total_packets);
        println!("Duration: {:.2}s", result.summary.duration_seconds);
        
        // Show first few packets
        println!("\n=== First 5 Packets ===");
        for packet in result.packets.iter().take(5) {
            println!("#{}: {} | {} bytes | {} → {} | {}", 
                packet.packet_number,
                packet.timestamp.split('T').nth(1).unwrap_or("").split('.').next().unwrap_or(""),
                packet.length,
                packet.src_ip.as_ref().unwrap_or(&"?".to_string()),
                packet.dst_ip.as_ref().unwrap_or(&"?".to_string()),
                packet.protocol.as_ref().unwrap_or(&"Unknown".to_string())
            );
        }
    }

    Ok(())
}
