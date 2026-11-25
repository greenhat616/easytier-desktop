fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "proto/spike.proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[proto], &["proto"])?;
    Ok(())
}
