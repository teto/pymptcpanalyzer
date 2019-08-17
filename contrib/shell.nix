# { pkgs ? import <nixpkgs> {} }:
with import <nixpkgs> {};

let
  mptcpanalyzer = callPackage ../default.nix {};

  # TODO override pandas
  prog = (mptcpanalyzer.override({
    # inherit pandas;
    # inherit cmd2;
  }) ).overridePythonAttrs (oa: {

    nativeBuildInputs = (oa.nativeBuildInputs or []) ++ [
      # to publish on pypi
      pkgs.python3Packages.twine
    ];
    propagatedBuildInputs  = (oa.propagatedBuildInputs  or []) ++ [
      my_nvim.config.python3Env
    ];

    src = ../.;

    # postShellHook = ''
    preShellHook = ''
      echo "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"
      export SOURCE_DATE_EPOCH=315532800
      export PATH="${my_nvim}/bin:$PATH"
      echo "importing a custom nvim ${my_nvim}"

      alias m=mptcpanalyzer

    '';

  });

  # https://www.reddit.com/r/neovim/comments/b1zm7h/how_to_setup_microsofts_python_lsp_in_linuxubuntu/
  my_nvim = genNeovim  [ mptcpanalyzer ] {
    # ms-python.python
    extraPython3Packages = ps: with ps;  [ python-language-server ];
  };

in
# TODO generate our own nvim
  prog
