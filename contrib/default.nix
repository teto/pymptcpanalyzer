{ stdenv
# can be overriden with the one of your choice
, poetry2nix
, pango
}:
let
  mptcpanalyzer = poetry2nix.mkPoetryApplication {
    projectDir = ../.;
    # preferWheels = false;
    overrides = poetry2nix.overrides.withDefaults (self: super: {

      pyqt5 = super.pyqt5.override { withMultimedia = true; };
      # pyqt5-qt = self.pyqt5_with_qtmultimedia;
      # pyqt5_qt = self.pyqt5_with_qtmultimedia;
      matplotlib = (super.matplotlib.override { enableGtk3=true;}).overrideAttrs(oa: {
        buildInputs = oa.buildInputs ++ [ pango ];
        strictDeps = false;
      });
    });
  };
in
  mptcpanalyzer
