{
stdenv
, fetchFromGitHub
# , buildPythonApplication
# , stevedore, cmd2
# might be useless ? depends on cmd2
# , pandas, matplotlib, pyqt5
, python3Packages

# can be overriden with the one of your choice
, tshark
}:
let
    pixcat = python3Packages.callPackage ./contrib/pixcat.nix {};
    # pandas = python3Packages.pandas.overridePythonAttrs (oa: {

    #   src = fetchFromGitHub {
    #     owner = "teto";
    #     repo = "pandas";
    #     rev = "7ab9ff579daebd6b16c357221850f85c7e218d97";
    #     sha256 = "0ixrvskbalhbbdp06x02dv24iqyrh2x3cqnlaxprc9y38bqr4b8b";
    #   };

    #   # src = super.fetchFromGitHub {
    #   #   owner = "pandas-dev";
    #   #   repo = "pandas";
    #   #   rev = "9c0f6a8d703b6bee48918f2c5d16418a7ff736e3";
    #   #   sha256 = "0czdfn82sp2mnw46n90xkfvfk7r0zgfyhfk0npnglp1jpfndpj3i";
    #   # };

    #   # to prevent "ZIP does not support timestamps before 1980"
    #   SOURCE_DATE_EPOCH=315532800;
    #   SETUPTOOLS_SCM_PRETEND_VERSION="0.25.0";
    #   doCheck = false;
    #   installCheckPhase = false;
    # });


    # cmd2 = python3Packages.cmd2.overridePythonAttrs(oa: rec {
    #   version = "0.9.18";
    #   src = builtins.fetchGit {
    #       url=https://github.com/python-cmd2/cmd2.git;
    #       # ref = "completion_state";
    #       # url=https://github.com/teto/cmd2.git;
    #       # ref = "completion_state_matt";
    #     };
    #     doCheck = false;
    #     SETUPTOOLS_SCM_PRETEND_VERSION = version;
    # });

in
python3Packages.buildPythonApplication rec {
	pname = "mptcpanalyzer";
	version = "0.3.2";

    src = fetchFromGitHub {
      owner = "teto";
      repo = "mptcpanalyzer";
      rev = "${version}";
      sha256 = "050s3kpxrz5xw70q2irl49v8zw8adf24m62gym6asvr3r1k87jbh";
    };

    doCheck = false;

    propagatedBuildInputs = with python3Packages; [
      bitmath
      cmd2
      stevedore pandas
      pixcat
      # we want gtk because qt is so annying on nixos
      # enableQt = true;
      (matplotlib.override { enableGtk3=true; })
      # pyqt5
      tshark
    ];

    meta = with stdenv.lib; {
      description = "pcap analysis tool specialized for multipath TCP.";
      maintainers = [ maintainers.teto ];
      license = licenses.gpl3;
    };
}
