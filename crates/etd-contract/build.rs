fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = ["proto/etd/v1/options.proto", "proto/etd/v1/host.proto"];
    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    let descriptor =
        std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("host_descriptor.bin");
    prost_build::Config::new()
        .file_descriptor_set_path(descriptor)
        .compile_protos(&protos, &["proto"])?;
    Ok(())
}
