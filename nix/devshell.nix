{ pkgs }:
pkgs.mkShell {
  packages = with pkgs; [
    # Command runner.
    just

    # Go toolchain.
    go

    # Rust toolchain.
    cargo
    rustfmt

    # C toolchain for compiling eBPF programs.
    llvmPackages_21.clang-tools
    llvmPackages_21.llvm

    # BPF libraries.
    libbpf
    linuxHeaders

    # Linters and Formatters
    golangci-lint
    shfmt
    gofumpt
    nixfmt-rfc-style
    nixd

    # Python for evaluation scripts.
    (python3.withPackages (
      ps: with ps; [
        matplotlib
      ]
    ))
  ];
}
