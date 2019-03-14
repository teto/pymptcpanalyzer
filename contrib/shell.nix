# { pkgs ? import <nixpkgs> {} }:
with import <nixpkgs> {};
let
    pandas = python3Packages.pandas.overridePythonAttrs (oa: {

      src = fetchFromGitHub {
        owner = "teto";
        repo = "pandas";
        rev = "7072085b82ed30a79b612962dba3d17a60d2c352";
        sha256 = "1i8mvgypcvbwdziqb3zw0z9cpnczz2k3814wqrb4v9a30rd6g66f";
      };

      # src = super.fetchFromGitHub {
      #   owner = "pandas-dev";
      #   repo = "pandas";
      #   rev = "9c0f6a8d703b6bee48918f2c5d16418a7ff736e3";
      #   sha256 = "0czdfn82sp2mnw46n90xkfvfk7r0zgfyhfk0npnglp1jpfndpj3i";
      # };

      doCheck = false;
      installCheckPhase = false;
    });

  # TODO override pandas
  prog = (mptcpanalyzer.override({ inherit pandas; }) ).overridePythonAttrs (oa: {

    propagatedBuildInputs = oa.propagatedBuildInputs ++ [
      # to publish on pypi
      pkgs.python3Packages.twine
      # is not added to PATH ?!
      my_nvim
    ];

    src = ../.;

    postShellHook = ''
      export SOURCE_DATE_EPOCH=315532800
      export PATH="${my_nvim}/bin:$PATH"
      echo "importing a custom nvim ${my_nvim}"

    '';

  });

  projectConfig = {
    extraPython3Packages = ps: with ps; ([
        jedi
        # add rope for completion ?
        urllib3
        mypy
        pyls-mypy # on le desactive sinon il genere des
        python-language-server
        pycodestyle
      ]);
  };

  my_nvim = genNeovim  [ mptcpanalyzer ] projectConfig;

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
