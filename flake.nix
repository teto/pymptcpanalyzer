{
  description = "Multipath tcp pcap analyzer tool";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    # poetry.url = "github:nix-community/poetry2nix";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }: let
  in flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      mptcpanalyzer = pkgs.callPackage ./contrib/default.nix {};
    in rec {

    packages.mptcpanalyzer = mptcpanalyzer;

    devShell = mptcpanalyzer;
    defaultPackage = mptcpanalyzer;
  });
}
