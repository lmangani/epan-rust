// rust-pcap-dissector/src/main.rs
use pcap_dissector::dissect_pcap;
use clap::{Arg, Command};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let matches = Command::new("pcap-dissector")
        .version("1.0")
        .about("Dissect pcap files using Wireshark's epan library")
        .arg(Arg::new("pcap")
            .help("The pcap file to analyze")
            .required(true)
            .index(1))
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .value_name("FILE")
            .help("Output file (default: stdout)")
            .num_args(1))
        .arg(Arg::new("format")
            .short('f')
            .long("format")
            .value_name("FORMAT")
            .help("Output format")
            .value_parser(["json", "csv", "summary"])
            .default_value("json"))
        .arg(Arg::new("limit")
            .short('n')
            .long("limit")
            .value_name("N")
            .help("Limit to first N packets")
            .num_args(1))
        .subcommand(Command::new("protocols")
            .about("List all protocols found in the pcap"))
        .subcommand(Command::new("flows")
            .about("Show network flows"))
        .get_matches();
    
    let pcap_file = matches.get_one::<String>("pcap").unwrap();
    
    match matches.subcommand() {
        Some(("protocols", _)) => {
            let result = dissect_pcap(pcap_file)?;
            println!("Protocols found:");
            for (protocol, count) in &result.summary.protocol_distribution {
                println!("  {}: {}", protocol, count);
            }
        }
        Some(("flows", _)) => {
            let result = dissect_pcap(pcap_file)?;
            let mut flows = std::collections::HashMap::new();
            for packet in &result.packets {
                if let (Some(src_ip), Some(dst_ip), Some(src_port), Some(dst_port)) = 
                    (&packet.src_ip, &packet.dst_ip, packet.src_port, packet.dst_port) {
                    let flow_key = format!("{}:{} <-> {}:{}", src_ip, src_port, dst_ip, dst_port);
                    let counter = flows.entry(flow_key).or_insert(0);
                    *counter += 1;
                }
            }
            
            println!("Top flows:");
            let mut flow_vec: Vec<_> = flows.iter().collect();
            flow_vec.sort_by(|a, b| b.1.cmp(a.1));
            
            for (flow, count) in flow_vec.iter().take(10) {
                println!("  {}: {} packets", flow, count);
            }
        }
        _ => {
            // Default: output based on format
            let format = matches.get_one::<String>("format").unwrap();
            let limit: Option<usize> = matches.get_one::<String>("limit")
                .map(|s| s.parse().unwrap_or(usize::MAX));
            
            let output = match format.as_str() {
                "json" => {
                    let mut result_copy = dissect_pcap(pcap_file)?;
                    if let Some(n) = limit {
                        result_copy.packets.truncate(n);
                    }
                    serde_json::to_string_pretty(&result_copy)?
                }
                "csv" => {
                    let result = dissect_pcap(pcap_file)?;
                    let mut csv = String::from("packet_num,timestamp,length,src_ip,dst_ip,src_port,dst_port,protocol\n");
                    let packets = if let Some(n) = limit {
                        &result.packets[..n.min(result.packets.len())]
                    } else {
                        &result.packets
                    };
                    
                    for packet in packets {
                        csv.push_str(&format!("{},{},{},{},{},{},{},{}\n",
                            packet.packet_number,
                            packet.timestamp,
                            packet.length,
                            packet.src_ip.as_ref().map_or("", |v| v),
                            packet.dst_ip.as_ref().map_or("", |v| v),
                            packet.src_port.unwrap_or(0),
                            packet.dst_port.unwrap_or(0),
                            packet.protocol.as_ref().map_or("", |v| v)
                                               ));
                    }
                    csv
                }
                "summary" => {
                    let result = dissect_pcap(pcap_file)?;
                    format!("File: {}\nPackets: {}\nProtocols: {}\nDuration: {:.2}s\nBytes: {}",
                        result.file_info.filename,
                        result.file_info.total_packets,
                        result.summary.protocol_distribution.len(),
                        result.summary.duration_seconds,
                        result.summary.total_bytes
                    )
                }
                _ => unreachable!(),
            };

            if let Some(output_file) = matches.get_one::<String>("output") {
                std::fs::write(output_file, output)?;
                println!("Output written to {}", output_file);
            } else {
                print!("{}", output);
            }
        }
    }

    Ok(())
}
