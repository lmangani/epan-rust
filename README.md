# rust-pcap-dissector/README.md
# Rust Pcap Dissector

A Rust library for dissecting pcap files using Wireshark's epan library, providing structured JSON output.

## Quick Start

```rust
use pcap_dissector::dissect_pcap_to_json;

let json_result = dissect_pcap_to_json("capture.pcap")?;
println!("{}", json_result);
