# { pkgs ? import <nixpkgs> {} }:
with import <nixpkgs> {};
# let
mptcpanalyzer.overrideAttrs (oa: {

    propagatedBuildInputs = oa.propagatedBuildInputs ++ [
      # to publish on pypi
      pkgs.python3Packages.twine
    ];

    src = ./.;

    # to work around 
    # https://nixos.org/nixpkgs/manual/#python-setup.py-bdist_wheel-cannot-create-.whl
    # also overriding shellHook breaks 
    postShellHook = ''
      export SOURCE_DATE_EPOCH=315532800

      which python3 > .nvimrc
      
    '';
})
