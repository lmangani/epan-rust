// rust-pcap-dissector/examples/export_csv.rs
use pcap_dissector::dissect_pcap;
use std::env;
use std::fs::File;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 3 {
        println!("Usage: {} <pcap_file> <output.csv>", args[0]);
        return Ok(());
    }

    let pcap_file = &args[1];
    let csv_file = &args[2];
    
    let result = dissect_pcap(pcap_file)?;
    let mut file = File::create(csv_file)?;
    
    // Write CSV header
    writeln!(file, "packet_num,timestamp,length,src_ip,dst_ip,src_port,dst_port,protocol")?;
    
    // Write packet data
    for packet in &result.packets {
        writeln!(file, "{},{},{},{},{},{},{},{}",
            packet.packet_number,
            packet.timestamp,
            packet.length,
            packet.src_ip.as_ref().unwrap_or(""),
            packet.dst_ip.as_ref().unwrap_or(""),
            packet.src_port.unwrap_or(0),
            packet.dst_port.unwrap_or(0),
            packet.protocol.as_ref().unwrap_or("")
        )?;
    }
    
    println!("Exported {} packets to {}", result.packets.len(), csv_file);
    Ok(())
}
