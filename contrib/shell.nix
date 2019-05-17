# { pkgs ? import <nixpkgs> {} }:
with import <nixpkgs> {};
let
    # pandas = python3Packages.pandas.overridePythonAttrs (oa: {

    #   src = fetchFromGitHub {
    #     owner = "teto";
    #     repo = "pandas";
    #     rev = "7072085b82ed30a79b612962dba3d17a60d2c352";
    #     sha256 = "1i8mvgypcvbwdziqb3zw0z9cpnczz2k3814wqrb4v9a30rd6g66f";
    #   };

    #   # src = super.fetchFromGitHub {
    #   #   owner = "pandas-dev";
    #   #   repo = "pandas";
    #   #   rev = "9c0f6a8d703b6bee48918f2c5d16418a7ff736e3";
    #   #   sha256 = "0czdfn82sp2mnw46n90xkfvfk7r0zgfyhfk0npnglp1jpfndpj3i";
    #   # };

    #   doCheck = false;
    #   installCheckPhase = false;
    # });
    cmd2 = python3Packages.cmd2.overridePythonAttrs(oa: {
        src = fetchgit {
          url=https://github.com/python-cmd2/cmd2.git;
          rev = "35d25d5aa33324fa0fa3ce74f5af48d246fc5361";
          sha256 = "0ig3c3av4vkkzcnv5m9nq0abf11kmc33djihxzfs5wbjisgdl0gi";
          leaveDotGit = true;
          deepClone = true;
        };
        doCheck = false;
    });

  # TODO override pandas
  prog = (mptcpanalyzer.override({
    # inherit pandas;
    # inherit cmd2;
  }) ).overridePythonAttrs (oa: {

    nativeBuildInputs = oa.propagatedBuildInputs ++ [
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

  my_nvim = genNeovim  [ mptcpanalyzer ] {};

in
# TODO generate our own nvim
  prog
