{
  description = "Multipath tcp pcap analyzer tool";

  inputs = {
    # inputs.nixpkgs.follows = "nixpkgs";
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    poetry = {
      url = "github:nix-community/poetry2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, poetry }: let
  in flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      mptcpanalyzer = pkgs.callPackage ./contrib/default.nix {};
    in rec {

    packages.mptcpanalyzer = mptcpanalyzer;
    defaultPackage = mptcpanalyzer;

    devShell = mptcpanalyzer;
    # devShell = pkgs.mkShell {
    #   name = "dev-shell";
    #   buildInputs = with pkgs; [
    #     defaultPackage.inputDerivation
    #     pkgs.nodePackages.pyright
    #     poetry.packages."${system}".poetry
    #   ];
    # };
  });
}
