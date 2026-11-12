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
    prost.enum_attribute(
        ".coolify.sentinel.control.v1.Command.payload",
        "#[allow(clippy::large_enum_variant)]",
    );

    // `ImageBuildRequest` carries Git credentials and `WorkloadDeployRequest`
    // the registry login, variables, and secret files; lib.rs redacts them.
    // Presigned S3 URLs of volume backups and restores, too. One call: a
    // second `skip_debug` replaces the first list.
    prost.skip_debug([
        ".coolify.sentinel.control.v1.ImageBuildRequest",
        ".coolify.sentinel.control.v1.WorkloadDeployRequest",
        ".coolify.sentinel.control.v1.VolumeBackupPartUrl",
        ".coolify.sentinel.control.v1.VolumeRestoreRequest",
    ]);

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_with_config(prost, &["proto/control.proto"], &["proto"])?;

    Ok(())
}
