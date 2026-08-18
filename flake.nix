{
  description = "nats-callout — NATS auth-callout crypto primitives for Ruby";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, utils }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        ruby = pkgs.ruby_3_4;
      in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = with pkgs; [
            ruby
            libyaml
            openssl

            # lefthook's pre-commit secret scan, and ripgrep because scampi
            # discovers the co-located `__END__` specs with it.
            trufflehog
            ripgrep

            # The ext/nats_callout binding (magnus + rb_sys).
            rustc
            cargo
            # rb_sys/magnus generate the Ruby bindings with bindgen, which needs
            # libclang at build time.
            clang
            libclang
          ];

          shellHook = ''
            export GEM_HOME="$HOME/.gem-${ruby.version}"
            export GEM_PATH="$GEM_HOME"
            export PATH="$GEM_HOME/bin:$PATH"
            export BUNDLE_GEMFILE="$PWD/Gemfile"
            export BUNDLE_PATH="$GEM_HOME"
            export BUNDLE_BIN="$GEM_HOME/bin"

            export LIBCLANG_PATH="${pkgs.libclang.lib}/lib"
          '';
        };
      }
    );
}
