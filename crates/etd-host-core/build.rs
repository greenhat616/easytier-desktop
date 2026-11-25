fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../etd-contract/proto/etd/v1/host.proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_prost_build::configure()
        .build_client(false)
        .build_server(true)
        .extern_path(".etd.v1", "::etd_contract::v1")
        .compile_protos(&[proto], &["../etd-contract/proto"])?;
    Ok(())
}
