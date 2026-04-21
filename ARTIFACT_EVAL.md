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

## Artifact 1: Micro-Benchmark

Run the micro-benchmark with:

```bash
nix run .#artifact-eval.micro-benchmark
```

This may take around 20 minutes.
Once finished, you should be presented with a table similar to table 5
in the paper:

```text
TODO
```

## Artifact 2: Macro-Benchmark
