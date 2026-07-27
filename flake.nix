{
  description = "Vigil CLI - Vulnerability scanner for JavaScript/TypeScript, Python, Rust, PHP, and Go projects";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        version = if (self ? rev) then self.rev else "dev";

      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "vigil";
          version = version;

          src = ./.;

          vendorHash = "sha256-/w/xyWnf/+aOmicu6K9AelN4D5QIPN7+SYwXyJ1lBsM=";

          ldflags = [
            "-X github.com/guttenbergovitz/vigil-cli/internal/version.Version=${version}"
            "-X github.com/guttenbergovitz/vigil-cli/internal/version.Commit=${version}"
            "-X github.com/guttenbergovitz/vigil-cli/internal/version.Date=1970-01-01T00:00:00Z"
          ];

          subPackages = [ "cmd/vigil" ];

          meta = with pkgs.lib; {
            description = "Vulnerability scanner for JavaScript/TypeScript, Python, Rust, PHP, and Go projects";
            homepage = "https://github.com/guttenbergovitz/vigil-cli";
            license = licenses.mit;
            maintainers = [ ];
          };
        };

        # Development shell with all tools
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go_1_24
            go-task
            git
          ];

          shellHook = ''
            echo "Vigil development environment"
            echo "Go version: $(go version)"
            echo "Task version: $(task --version)"
          '';
        };

        # Apps for nix run
        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/vigil";
        };
      }
    );
}
