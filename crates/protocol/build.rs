fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/control.proto");

    let mut prost = prost_build::Config::new();
    prost.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    prost.enum_attribute(
        ".coolify.sentinel.control.v1.AgentMessage.message",
        "#[allow(clippy::large_enum_variant)]",
    );
    prost.enum_attribute(
        ".coolify.sentinel.control.v1.ControlMessage.message",
        "#[allow(clippy::large_enum_variant)]",
    );
    prost.enum_attribute(
        ".coolify.sentinel.control.v1.CommandResult.payload",
        "#[allow(clippy::large_enum_variant)]",
    );

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_with_config(prost, &["proto/control.proto"], &["proto"])?;

    Ok(())
}
