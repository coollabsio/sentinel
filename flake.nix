{
  description = "Sentinel development shell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = inputs @ {flake-parts, ...}:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem = {
        system,
        pkgs,
        ...
      }: {
        # fenix as an overlay on top of nixpkgs
        _module.args.pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [inputs.fenix.overlays.default];
        };

        devShells.default = let
          # Rust toolchain pinned by rust-toolchain.toml (channel 1.97.1 +
          # rustfmt/clippy).
          #
          # rust-toolchain.toml only declares intent ("channel 1.97.1"), so
          # fenix downloads the release manifest channel-rust-1.97.1.toml to
          # learn the component URLs and hashes. Flakes evaluate purely, so
          # that fetch needs a fixed-output hash — that's what this sha256
          # is: the hash of the *manifest*, not of rust-toolchain.toml and
          # not of the toolchain binaries (those are verified by the hashes
          # inside the manifest).
          #
          # When rust-toolchain.toml moves to a new channel, set this to
          # pkgs.lib.fakeSha256 and copy the real hash from the error
          # message of `nix develop`.
          rustToolchain = pkgs.fenix.fromToolchainFile {
            file = ./rust-toolchain.toml;
            sha256 = "sha256-A1abGIbOtcBSdrUMhDGrER3pRM1hQP4fp9gh3Y4PKc8=";
          };
        in
          pkgs.mkShell {
            packages = with pkgs; [
              rustToolchain
              cargo-watch
              gcc
              podman
            ];
          };
      };
    };
}
