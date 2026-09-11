fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/control.proto");

    let mut prost = prost_build::Config::new();
    prost.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_with_config(prost, &["proto/control.proto"], &["proto"])?;

    Ok(())
}
