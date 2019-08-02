# { pkgs ? import <nixpkgs> {} }:
with import <nixpkgs> {};

let
  # TODO override pandas
  prog = (mptcpanalyzer.override({
    # inherit pandas;
    # inherit cmd2;
  }) ).overridePythonAttrs (oa: {

    # nativeBuildInputs = (oa.nativeBuildInputs or []) ++ [
    #   # to publish on pypi
    #   # pkgs.python3Packages.twine
    # ];
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

    '';

  });

  my_nvim = genNeovim  [ mptcpanalyzer ] {
    extraPython3Packages = ps: with ps;  [ python-language-server ];
  };

in
# TODO generate our own nvim
  prog
