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
      # mptcpanalyzer = pkgs.callPackage ./contrib/default.nix {};
    in rec {


    packages.mptcpanalyzer = pkgs.poetry2nix.mkPoetryApplication {
      projectDir = ./.;
      overrides = pkgs.poetry2nix.overrides.withDefaults (final: prev: {
        # matplotlib = pkgs.python3Packages.matplotlib;
        matplotlib = prev.matplotlib.overrideAttrs (old: {
        # see https://github.com/nix-community/poetry2nix/issues/280 as to why
        propagatedBuildInputs = (old.propagatedBuildInputs or [ ]) ++ [
          final.certifi
        ];
        });
      });
    };
    defaultPackage = self.packages."${system}".mptcpanalyzer;

    devShell = pkgs.mkShell {

      buildInputs = [
        (pkgs.poetry2nix.mkPoetryEnv {
          projectDir = ./.;
        })
        pkgs.nodePackages.pyright
        poetry.packages."${system}".poetry
      ];

      # shellHook ?
    };
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
