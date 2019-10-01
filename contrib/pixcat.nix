{ stdenv, buildPythonPackage, fetchPypi
, blessed, docopt, pillow, requests, dataclasses
}:
buildPythonPackage rec {
  pname = "pixcat";
  version = "0.1.4";

  src = fetchPypi {
    inherit pname version;
    sha256 = "1dmbwymqkmwwrdib2qgpq2sbcpdqlix38sq8sv6frjhk8ph8yz35";
  };

  # patchPhase = ''
  #   substituteInPlace setup.py \
  #       --replace '/usr/include/mupdf' ${mupdf.dev}/include/mupdf
  #   '';
  # nativeBuildInputs = [ swig ];
  propagatedBuildInputs = [
    blessed
    # dataclasses
    docopt
    pillow
    requests
  ];
  doCheck = false;

  meta = with stdenv.lib; {
    description = "PDF file reader/writer library.";
    homepage = https://github.com/pmaupin/pdfrw;
    maintainers = with maintainers; [ teto ];
    license = licenses.mit;
  };
}

