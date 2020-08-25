{ stdenv
# can be overriden with the one of your choice
, poetry2nix
, pango
}:
let
  mptcpanalyzer = poetry2nix.mkPoetryApplication {
    projectDir = ../.;
    preferWheels = false;
    overrides = poetry2nix.overrides.withDefaults (self: super: {

      matplotlib = (super.matplotlib.override { enableGtk3=true;}).overrideAttrs(oa: {
        buildInputs = oa.buildInputs ++ [ pango ];
        strictDeps = false;
      });
    });
  };
in
  mptcpanalyzer
