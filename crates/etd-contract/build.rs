fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/etd/v1/host.proto";
    println!("cargo:rerun-if-changed={proto}");
    let descriptor =
        std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("host_descriptor.bin");
    prost_build::Config::new()
        .file_descriptor_set_path(descriptor)
        .compile_protos(&[proto], &["proto"])?;
    Ok(())
}
