{ stdenv
# can be overriden with the one of your choice
, poetry2nix
, pango
, qhull
}:
let
  mptcpanalyzer = poetry2nix.mkPoetryApplication {
    projectDir = ../.;
    overrides = poetry2nix.overrides.withDefaults (final: prev: {
      matplotlib = prev.matplotlib.overrideAttrs (old: {
      # see https://github.com/nix-community/poetry2nix/issues/280 as to why
      propagatedBuildInputs = (old.propagatedBuildInputs or [ ]) ++ [ final.certifi qhull ];
      });
    });
  };
in
  mptcpanalyzer
