{ pkgs ? import <nixpkgs> {} }:
let
  m = pkgs.mptcpanalyzer.overrideAttrs (oa: {
    src = ./.;
  });
in
    m
