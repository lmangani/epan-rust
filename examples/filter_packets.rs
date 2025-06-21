// rust-pcap-dissector/examples/filter_packets.rs
use pcap_dissector::dissect_pcap;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 3 {
        println!("Usage: {} <pcap_file> <filter>", args[0]);
        println!("Filters: http, https, dns, ssh, tcp, udp");
        return Ok(());
    }

    let pcap_file = &args[1];
    let filter = &args[2].to_lowercase();
    
    let result = dissect_pcap(pcap_file)?;
    
    let filtered_packets: Vec<_> = result.packets.iter()
        .filter(|packet| {
            match filter.as_str() {
                "http" => packet.dst_port == Some(80) || packet.src_port == Some(80),
                "https" => packet.dst_port == Some(443) || packet.src_port == Some(443),
                "dns" => packet.dst_port == Some(53) || packet.src_port == Some(53),
                "ssh" => packet.dst_port == Some(22) || packet.src_port == Some(22),
                "tcp" => packet.protocols.contains(&"TCP".to_string()),
                "udp" => packet.protocols.contains(&"UDP".to_string()),
                _ => false,
            }
        })
        .collect();

    println!("Found {} {} packets out of {} total", 
        filtered_packets.len(), filter, result.file_info.total_packets);

    for packet in filtered_packets.iter().take(20) {
        println!("#{}: {} | {}:{} → {}:{} | {} bytes", 
            packet.packet_number,
            packet.timestamp.split('T').nth(1).unwrap_or("").split('.').next().unwrap_or(""),
            packet.src_ip.as_ref().unwrap_or(&"?".to_string()),
            packet.src_port.unwrap_or(0),
            packet.dst_ip.as_ref().unwrap_or(&"?".to_string()),
            packet.dst_port.unwrap_or(0),
            packet.length
        );
    }

    Ok(())
}
