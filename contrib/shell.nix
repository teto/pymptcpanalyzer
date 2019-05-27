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
      # src = fetchgit
      src = builtins.fetchGit {
          url=https://github.com/python-cmd2/cmd2.git;
          # url=https://github.com/teto/cmd2.git;
          # rev = "c0545b1c939f4aeb281e498a834e59ae5e38ce48";
          ref = "script_refactor";
          # ref = "master";
          # sha256 = "1i08jlc95al6kna81nl3fh3ka143mz2q967hd08dvjm952w6j5mx";
          # leaveDotGit = true;
          # deepClone = true;
        };
        doCheck = false;
        SETUPTOOLS_SCM_PRETEND_VERSION="0.9.13";
    });

  # TODO override pandas
  prog = (mptcpanalyzer.override({
    # inherit pandas;
    inherit cmd2;
  }) ).overridePythonAttrs (oa: {

    # nativeBuildInputs = (oa.nativeBuildInputs or []) ++ [
    #   # to publish on pypi
    #   # pkgs.python3Packages.twine
    # ];
    propagatedBuildInputs  = (oa.propagatedBuildInputs  or []) ++ [
      my_nvim.config.python3Env
    ];

    src = ../.;

    postShellHook = ''
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
