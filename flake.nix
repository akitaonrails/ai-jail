{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      pre-commit-hooks,
      rust-overlay,
      treefmt-nix,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        inherit (pkgs) mkShell;

        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        # Only rustc + cargo + rust-std are needed to actually *build* the
        # package. `rust` above also drags in rustfmt/clippy/rust-analyzer/
        # rust-src/rust-docs/llvm-tools (whatever rust-toolchain.toml asks
        # for), and since they're all part of the same aggregated
        # derivation, their /nix/store paths get embedded as plain strings
        # in the compiled binary (panic locations, debug info, etc.) and
        # end up as spurious runtime dependencies of the final package.
        rustBuild = pkgs.rust-bin.fromRustupToolchain {
          channel = (builtins.fromTOML (builtins.readFile ./rust-toolchain.toml)).toolchain.channel;
        };

        rustPlatform = pkgs.makeRustPlatform {
          rustc = rustBuild;
          cargo = rustBuild;
        };

        formatter =
          (treefmt-nix.lib.evalModule pkgs {
            projectRootFile = "flake.nix";

            settings = {
              allow-missing-formatter = true;
              verbose = 0;

              global.excludes = [ "*.lock" ];

              formatter = {
                nixfmt.options = [ "--strict" ];
                rustfmt.package = rust;
              };
            };

            programs = {
              nixfmt.enable = true;
              prettier.enable = true;
              rustfmt = {
                enable = true;
                package = rust;
              };
              taplo.enable = true;
            };
          }).config.build.wrapper;

        pre-commit-check = pre-commit-hooks.lib.${system}.run {
          src = ./.;

          hooks = {
            deadnix.enable = true;
            nixfmt.enable = true;
            treefmt = {
              enable = true;
              package = formatter;
            };
          };
        };
      in
      {
        packages.default = rustPlatform.buildRustPackage {
          name = "ai-jail";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [
            pkgs.makeWrapper
            pkgs.bubblewrap
          ];

          BWRAP_BIN = "${pkgs.bubblewrap}/bin/bwrap";

          # Belt-and-suspenders: strip any /nix/store path that might still
          # get baked into the binary (panic!()/file!() locations, debug
          # info, ...) so Nix's reference scanner has nothing left to
          # falsely latch onto, even for the now-much-smaller build toolchain.
          RUSTFLAGS = "--remap-path-prefix=${builtins.storeDir}=/build";

          postFixup = ''
            wrapProgram "$out/bin/ai-jail" \
              --set BWRAP_BIN "${pkgs.bubblewrap}/bin/bwrap"
          '';
        };

        formatter = formatter;

        checks = { inherit pre-commit-check; };

        devShells.default = mkShell {
          name = "ai-jail";

          buildInputs = [
            rust
            formatter
            pkgs.bubblewrap
          ];

          shellHook = ''
            export BWRAP_BIN="${pkgs.bubblewrap}/bin/bwrap"
          '';
        };
      }
    );
}
