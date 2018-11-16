{ pkgs ? import <nixpkgs> {} }:
let
  m = pkgs.mptcpanalyzer.overrideAttrs (oa: {

    propagatedBuildInputs = oa.propagatedBuildInputs ++ [
      # to publish on pypi
      pkgs.python3Packages.twine
    ];

    src = ./.;

    # to work around 
    # https://nixos.org/nixpkgs/manual/#python-setup.py-bdist_wheel-cannot-create-.whl
    shellHook = ''
      export SOURCE_DATE_EPOCH=315532800
    '';
  });
in
    m
