# { pkgs ? import <nixpkgs> {} }:
with import <nixpkgs> {};
let
  prog = mptcpanalyzer.overridePythonAttrs (oa: {

    propagatedBuildInputs = oa.propagatedBuildInputs ++ [
      # to publish on pypi
      pkgs.python3Packages.twine
    ];

    src = ../.;

  });

  # pythonLibs = with ps; ;
  pythonEnv = python3.withPackages(ps: with ps; [
      jedi
      urllib3
      mypy
      pyls-mypy # on le desactive sinon il genere des
      python-language-server
      pycodestyle
    ]);
in
# TODO generate our own nvim
mkShell {

  buildInputs = [ prog pythonEnv ];
    # to work around
    # https://nixos.org/nixpkgs/manual/#python-setup.py-bdist_wheel-cannot-create-.whl
    # also overriding shellHook breaks
    # helps working around neomake + nix limitations
    shellHook = ''
      export SOURCE_DATE_EPOCH=315532800

      echo "hello world"
      # set -x
# https://github.com/teto/mptcpanalyzer/commit/11d6d9a3c2a1f730c9ec84ac885fbfe6a065f064
      # echo "let g:python3_host_prog='$(which python3)'" > .nvimrc
      echo "call UpdatePythonHost('${pythonEnv.interpreter}')" > .nvimrc
    '';

}
