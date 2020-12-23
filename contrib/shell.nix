let
  nixpkgsRev = "e9158eca70ae59e73fae23be5d13d3fa0cfc78b4";
  # pinned nixpkgs before cabal 3 becomes the default else hie fails
  # nixpkgs = import <nixpkgs>
  nixpkgs = builtins.fetchTarball {
      name = "nixos-unstable";
      url = "https://github.com/nixos/nixpkgs/archive/${nixpkgsRev}.tar.gz";
      sha256 = "0cnmvnvin9ixzl98fmlm3g17l6w95gifqfb3rfxs55c0wj2ddy53";
  };

  pkgs = import nixpkgs {
    overlays = [
      # latest version of poetry and poetry2nix
      (import "${poetry2nixSrc}/overlay.nix")
    ];
  };

  # temporary overlay (remove on next nixpkgs bump)
  poetry2nixRev = "f0cc43e09f6adbbde8c1207d511cd124cdca28f4";
  poetry2nixSrc = (fetchTarball {
    url = "https://github.com/teto/poetry2nix/archive/${poetry2nixRev}.tar.gz";
    sha256 = "020qpwprkb52gimvmipixc7zqqmaxagxw9ddr75yf762s312byi3";
  });

  mptcpanalyzer = pkgs.callPackage ./default.nix {};

  # needed to support mptcp-v1
  # my_tshark = pkgs.tshark.overrideAttrs ( oa: {
  #   src = pkgs.fetchFromGitHub {
  #     repo   ="wireshark";
  #     owner  ="teto";
  #     rev    = "fd1dd72d8e8d2025b25c1485efc2cdee5eee589a";
  #     sha256 = "4GWiHGi4tnixeuQwPQ7IdLh5eIjtyQGYuzSky60Onmo=";
  #   };
  # });


  # TODO either it should take
  generatedNvimConfig = pkgs.neovimUtils.makeNeovimConfig {
    extraPython3Packages = ps: with ps; [ pkgs.nodePackages.pyright ];
  };

  # generatedNvimConfig.neovimRcContent
  # let g:python3_host_prog='/nix/store/3x7swg0ar6h7bm83av2p4lri3sr4lfs3-python3-3.8.6-env/bin/python3'
  finalNvimRcContent = ''
    luafile lsp_python.lua
  '';

  myMptcpAnalyzer = mptcpanalyzer.overridePythonAttrs (oa: {
    buildInputs = oa ++ [
      pkgs.poetry
      pkgs.gobjectIntrospection # otherwise Namespace Gtk not available
      pkgs.wrapGAppsHook  # check GDK_PIXBUF_MODULE_FILE
      pkgs.pango # Typelib file for namespace 'Pango', version '1.0' not found
      pkgs.gdk-pixbuf # Typelib file for namespace 'GdkPixbuf', version '2.0' not found
      pkgs.atk # Typelib file for namespace 'Atk', version '1.0' not found
    ];

    shellHook = oa.shellHook + ''
      alias m=mptcpanalyzer
      export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:${pkgs.stdenv.cc.cc.lib}/lib"
      echo '${pkgs.lib.traceVal finalNvimRcContent}' > .nvimrc
      # equivalent to an editable install/develop mode
      export PYTHONPATH=".:$PYTHONPATH"

      echo "${mptcpanalyzer.passthru.python.interpreter}"

    '';
  });

  # myShell = pkgs.mkShell {
  #   buildInputs = [
  #     mptcpanalyzer
  #     pkgs.poetry
  #     pkgs.gobjectIntrospection # otherwise Namespace Gtk not available
  #     pkgs.wrapGAppsHook  # check GDK_PIXBUF_MODULE_FILE
  #     pkgs.pango # Typelib file for namespace 'Pango', version '1.0' not found
  #     pkgs.gdk-pixbuf # Typelib file for namespace 'GdkPixbuf', version '2.0' not found
  #     pkgs.atk # Typelib file for namespace 'Atk', version '1.0' not found
  #   ];

  #   shellHook = ''
  #     alias m=mptcpanalyzer
  #     export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:${pkgs.stdenv.cc.cc.lib}/lib"
  #     echo '${pkgs.lib.traceVal finalNvimRcContent}' > .nvimrc
  #     # equivalent to an editable install/develop mode
  #     export PYTHONPATH=".:$PYTHONPATH"

  #     echo "${mptcpanalyzer.passthru.python.interpreter}"

  #   '';
  # };
in
  # myShell
  mptcpanalyzer
