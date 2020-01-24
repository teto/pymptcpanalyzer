with import <nixpkgs> {};

let
  mptcpanalyzer = callPackage ../default.nix {};

  # TODO override pandas
  prog = (mptcpanalyzer.override({
    # inherit pandas;
    # inherit cmd2;
  })).overridePythonAttrs (oa: {


    version = "0.3.3-dev";
    nativeBuildInputs = (oa.nativeBuildInputs or []) ++ [
      # to publish on pypi
      pkgs.python3Packages.twine
    ];
    propagatedBuildInputs  = (oa.propagatedBuildInputs  or []) ++ [
      my_nvim.config.python3Env

      # temporary addition to work with mpls
      openssl
    ];

    src = ../.;

    # postShellHook = ''
    # export PATH="${my_nvim}/bin:$PATH"
    #   echo "importing a custom nvim ${my_nvim}"
    postShellHook = ''
      export SOURCE_DATE_EPOCH=315532800
      echo "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"
      export PYTHONPATH="$tmp_path/lib/python3.7/site-packages:$PYTHONPATH"
      python -m pip install -e . --prefix $tmp_path >&2
      export PATH="${my_nvim}/bin:$PATH"
      echo "importing a custom nvim ${my_nvim}"

      alias m=mptcpanalyzer
    '';

  });


  # https://www.reddit.com/r/neovim/comments/b1zm7h/how_to_setup_microsofts_python_lsp_in_linuxubuntu/
  my_nvim = genNeovim  [ mptcpanalyzer ] {
    # ms-python.python
    # coc-python

    # plugins = [ vimPlugins.coc-python ];
    # configure = {
    #     packages.myVimPackage = {
    #       # see examples below how to use custom packages
    #       # loaded on launch
    #       start = startPlugins;
    # };

    configure.packages.myVimPackage.start = [ vimPlugins.coc-python ];
    # extraPython3Packages = ps: with ps;  [ python-language-server ];
  };

in
# TODO generate our own nvim
  prog
