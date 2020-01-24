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

    bitmath = python3Packages.bitmath.overridePythonAttrs(oa: {
      # src = fetchFromGitHub {
      #   owner = "tbielawa";
      #   repo = "bitmath";
      #   rev = "19a06eceb464c83899352bc9ebfe2d5e0b9ffa22";
      #   sha256 = "076vnaf6ss7fjqknd1s0kn10q6sh1j075bk6xxr3jycb3593i5f2";
      # };
      name = "bitmath-custom";
      src = builtins.fetchGit {
        url = https://github.com/teto/bitmath.git;
        ref = "fix_check";
      };

      doCheck = false;
    });

    # pandas = python3Packages.pandas.overridePythonAttrs (oa: {
    #   # src = fetchFromGitHub {
    #   #   owner = "teto";
    #   #   repo = "pandas";
    #   #   rev = "54018123cfdfec3d3111fc6d7fad9ac8eec5bdcb";
    #   #   sha256 = "0ixrvskbalhbbdp06x02dv24iqyrh2x3cqnlaxprc9y38bqr4b8b";
    #   # };
    #   src = fetchFromGitHub {
    #     owner = "pandas-dev";
    #     repo = "pandas";
    #     rev = "7ab9ff579daebd6b16c357221850f85c7e218d97";
    #     sha256 = "2hhlWXljxTY5EdGOGJDUYXSw9FHJsXj/qZIApygXDcE=";
    #   };
    #   # to prevent "ZIP does not support timestamps before 1980"
    #   SOURCE_DATE_EPOCH=315532800;
    #   SETUPTOOLS_SCM_PRETEND_VERSION="0.26.0";
    #   SETUPTOOLS_SCM_DEBUG=1;
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

    # needed to support mptcp-v1
    my_tshark = tshark.overrideAttrs ( oa: {
      # src = builtins.fetchGit {
      #   url = http://github.com/wireshark/wireshark.git;
      # };

    src = fetchFromGitHub {
        repo   ="wireshark";
        owner  ="teto";
        rev    = "fd1dd72d8e8d2025b25c1485efc2cdee5eee589a";
        sha256 = "4GWiHGi4tnixeuQwPQ7IdLh5eIjtyQGYuzSky60Onmo=";
      };
    });
in
python3Packages.buildPythonApplication rec {
	pname = "mptcpanalyzer";
	version = "0.3.3";

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
      jsonschema
      stevedore pandas
      pixcat
      # we want gtk because qt is so annying on nixos
      # enableQt = true;
      (matplotlib.override { enableGtk3=true; })
      # pyqt5
      my_tshark
    ];

    meta = with stdenv.lib; {
      description = "pcap analysis tool specialized for multipath TCP.";
      maintainers = [ maintainers.teto ];
      license = licenses.gpl3;
    };
}
