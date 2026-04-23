{
  lib,
  writeShellApplication,
  phoronix-test-suite,
}:
writeShellApplication {
  name = "macro-benchmark";

  runtimeInputs = [ phoronix-test-suite ];

  text = lib.readFile ./macro-benchmark.sh;
}
