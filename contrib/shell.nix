# { pkgs ? import <nixpkgs> {} }:
with import <nixpkgs> {};
let
  prog = mptcpanalyzer.overridePythonAttrs (oa: {

    propagatedBuildInputs = oa.propagatedBuildInputs ++ [
      # to publish on pypi
      pkgs.python3Packages.twine
    ];

    src = ../.;
    buildInputs = (oa.buildInputs or []) ++ [ my_nvim nvimConfig.python3Env ];

    postShellHook = ''
      export SOURCE_DATE_EPOCH=315532800

    '';

  });

  # pythonLibs = with ps; ;

  python3PackagesFun = ps: with ps; ([
      jedi
      # add rope for completion ?
      urllib3
      mypy
      pyls-mypy # on le desactive sinon il genere des
      python-language-server
      pycodestyle
    ]);
  nvimConfig = neovimConfig (lib.mkMerge [
    neovimDefaultConfig
    {
      extraPython3Packages = python3PackagesFun;
    }
  ]);

  # wrapNeovim neovim-unwrapped
  my_nvim = wrapNeovim neovim-unwrapped (
    lib.mkMerge [
    neovimDefaultConfig
    {
      extraPython3Packages = python3PackagesFun;
    }
    ]
  );

in
# TODO generate our own nvim
  prog
# mkShell {

#   buildInputs = [ prog my_nvim nvimConfig.python3Env ];
#     # to work around
#     # https://nixos.org/nixpkgs/manual/#python-setup.py-bdist_wheel-cannot-create-.whl
#     # also overriding shellHook breaks
#     # helps working around neomake + nix limitations
# #       echo "hello world"
# #       # set -x
# # # https://github.com/teto/mptcpanalyzer/commit/11d6d9a3c2a1f730c9ec84ac885fbfe6a065f064
# #       # echo "let g:python3_host_prog='$(which python3)'" > .nvimrc
# #       echo "call UpdatePythonHost('${pythonEnv.interpreter}')" > .nvimrc

# }
