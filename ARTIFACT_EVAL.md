# Artifact Evaluation

This document describes how to reproduce the artifacts of SemSan for
the sake of evaluation.

## Machine Configuration

For the paper, we ran the benchmarks on a GCP machine with the
following specifications:

- Machine Type: `c4d-standard-8`
- CPU Platform: AMD EPYC 9B45 (Turin) (x86_64)
- CPU Cores: 4 vCPU, 8 threads
- Memory: 32 GB

While the benchmark results *should* proportionally translate to other
machines, *exact* reproducibility of the results is only likely on the
same configuration.

In any case, an x86_64-Linux machine is required to reproduce the
results.

## Prerequisites

For the dependencies, refer to the [main README](../README.md). The
following sections of this document assume that a properly configured
Nix installation is present as described in the
[main README](../README.md).

When the dependencies are present, enter the Nix development shell
with:

```bash
nix develop
```

Then, generate the BPF bindings:

```bash
just codegen # This might take up to 5 minutes
```

Once the BPF bindings are generated, build the SemSan CLI:

```bash
just build
```

## Artifact 1: Sanitizer Correctness

In the [test](/test/) directory, for each sanitizer, there are program
samples that trigger a certain sanitizer, one that's triggering
sanitization and one that doesn't.

To exercise the test suite, run the [test entrypoint](/test/main_test.go)
with:

```bash
# Assuming you're still in the Nix shell with `nix develop`
just test
```

## Artifact 2: Micro-Benchmark

Run the micro-benchmark with:

```bash
nix run .#artifact-eval.micro-benchmark
```

This may take around 20 minutes.
Once finished, you should be presented with a table similar to table 5
in the paper:

```text
Benchmark                    Med w/o SemSan      Med w/ SemSan     Overhead %
---------                   ---------------      -------------     ----------
benchmark-general                3245004.00         3020300.00           6.92
benchmark-symlinkmount            501148.00          494376.00           1.35
benchmark-dirownership          36233952.00        36231305.00           0.01
benchmark-canary                36235571.00        18829935.00          48.03
```

## Artifact 3: Macro-Benchmark
