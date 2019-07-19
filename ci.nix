# with import (builtins.fetchTarball https://nixos.org/channels/nixpkgs-unstable {});
with import (builtins.fetchTarball https://nixos.org/channels/nixos-unstable/nixexprs.tar.xz) { };

let
   prog = callPackage ./default.nix {};
in
  prog.overridePythonAttrs (oa: {

    # nativeBuildInputs = (oa.nativeBuildInputs or []) ++ [
    #   # to publish on pypi
    #   # pkgs.python3Packages.twine
    # ];

    src = ./.;
  })


