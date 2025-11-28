{ pkgs ? import <nixpkgs> { config.allowUnfree = true; } }:

pkgs.mkShell {
  buildInputs = [
    pkgs.go
    pkgs.goreleaser
  ];
}