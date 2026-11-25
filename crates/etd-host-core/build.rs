fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protos = [
        "../etd-contract/proto/etd/v1/options.proto",
        "../etd-contract/proto/etd/v1/host.proto",
    ];
    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    tonic_prost_build::configure()
        .build_client(false)
        .build_server(true)
        .extern_path(".etd.v1", "::etd_contract::v1")
        .compile_protos(&protos, &["../etd-contract/proto"])?;
    Ok(())
}
