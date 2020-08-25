{
  description = "Multipath tcp pcap analyzer tool";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }: let
    mptcpanalyzer = nixpkgs.lib.callPackage ./default.nix {};
  in {

    packages.x86_64-linux.mptcpanalyzer = mptcpanalyzer;

    devShell = mptcpanalyzer;
    defaultPackage = mptcpanalyzer;
  };
}
