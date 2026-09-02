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
          overlays = [
            (import rust-overlay)
            # crates.io rejects any User-Agent containing the `curl/` token,
            # and nixpkgs' fetchurl builder identifies itself as
            # "curl/$curlVersion Nixpkgs/$nixpkgsVersion" — so every crate
            # fetch is refused with a 403 and `nix build` cannot vendor
            # anything. Verified directly against the download endpoint:
            # "curl/8.16.0 Nixpkgs/25.11" -> 403, "Nixpkgs/25.11" -> 200.
            #
            # builder.sh appends curlOptsList after its own --user-agent, and
            # curl honours the last one given, so this replaces the UA without
            # patching nixpkgs. fetchurl is an overridable functor rather than
            # a bare lambda, so keep its attributes (`override` and friends)
            # and swap only __functor — replacing the whole value with a
            # lambda breaks every caller that reaches for fetchurl.override.
            #
            # Only the request header changes: these are fixed-output
            # derivations, so sha256 still pins exactly what is fetched and
            # substitution from cache.nixos.org is unaffected. Remove once
            # nixpkgs stops sending a UA that crates.io blocks.
            (final: prev: {
              fetchurl = prev.fetchurl // {
                __functor =
                  _: args:
                  prev.fetchurl (
                    args
                    // {
                      curlOptsList = (args.curlOptsList or [ ]) ++ [
                        "--user-agent"
                        "Nixpkgs-ai-jail"
                      ];
                    }
                  );
              };
            })
          ];
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
