// rust-pcap-dissector/build.rs
use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to look for shared libraries in standard locations
    println!("cargo:rustc-link-lib=wireshark");
    println!("cargo:rustc-link-lib=glib-2.0");
    println!("cargo:rustc-link-lib=gobject-2.0");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // Add common library search paths
    if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-search=/usr/lib/x86_64-linux-gnu");
        println!("cargo:rustc-link-search=/usr/lib");
        println!("cargo:rustc-link-search=/usr/local/lib");
    } else if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-search=/usr/local/lib");
        println!("cargo:rustc-link-search=/opt/homebrew/lib");
    }

    // Try to find wireshark installation
    let wireshark_path = find_wireshark_installation();
    if let Some(path) = wireshark_path {
        println!("cargo:rustc-link-search={}/lib", path);
        println!("cargo:include={}/include", path);
    }

    // Set up pkg-config for glib
    pkg_config::Config::new()
        .atleast_version("2.0")
        .probe("glib-2.0")
        .unwrap();
}

fn find_wireshark_installation() -> Option<String> {
    // Common installation paths
    let paths = vec![
        "/usr",
        "/usr/local", 
        "/opt/wireshark",
        "/Applications/Wireshark.app/Contents/Resources",
    ];

    for path in paths {
        let lib_path = format!("{}/lib", path);
        if std::path::Path::new(&lib_path).exists() {
            return Some(path.to_string());
        }
    }
    None
}
