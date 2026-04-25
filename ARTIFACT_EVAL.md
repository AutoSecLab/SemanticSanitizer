# Artifact Evaluation

This document describes how to reproduce the artifacts of SemSan for
the sake of evaluation.

## Machine Configuration

To replicate our experiment, rely on a machine with the following
specifications:

- CPU Platform: AMD EPYC 9B45 (Turin) (x86_64)
- CPU Cores: 4 CPU, 8 threads
- Memory: 32 GB
- OS: `**TODO** which os did you test it?`

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

For an host machine based on Ubuntu, follow these commands:

```bash
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
source /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
```

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

## RQ1: Vulnerabilities Detected in the Wild (Sec 7.1)

**TODO**: Here, reproduce the bugs you find for which you have a public ID
(issue or CVE), at least those that are publically available. You can go for a
fuzzing campaign, or simply re-play the PoC. 

## RQ2: Detection Accuracy (Sec 7.2)

This experiment stresses the capability of SemSan to detect existing bugs. For
the sake of the artifact evaluation, we provide experiments for positive errors.
As our false positive analysis required months, we only describe how to install
the tool at system level.

### True Positive Detection

To simplify the detection of true positive, we prepared a suite of program
samples that trigger a certain sanitizer, one that's triggering sanitization and
one that doesn't. The tests are contained in the [test](/test/) directory.

To exercise the test suite, run the [test entrypoint](/test/main_test.go)
with:

```bash
# Assuming you're still in the Nix shell with `nix develop`
just test
```

**Expected output:** ``**TODO** :What should I see?``

### System Level Installation
```
**TODO**: How can we install SemSan in the system to
simulate general interaction? For this, we can't provide something that generate numbres, but I want to give the opportunity to try to tool freerly.
```

## RQ3: Performance Overhead (Sec 7.3)

### Micro-Benchmark

Run the micro-benchmark with:

```bash
nix run .#artifact-eval.micro-benchmark
```

This may take around 20 minutes.

**Expected Output:** Once finished, you should be presented with a table similar
to table 5 in the paper:

```text
Benchmark                    Med w/o SemSan      Med w/ SemSan     Overhead %
---------                   ---------------      -------------     ----------
benchmark-general                3229168.00         3032532.00           6.09
benchmark-symlinkmount            499868.00          494137.00           1.15
benchmark-dirownership          27593849.00        25398242.00           7.96
benchmark-canary                 3228323.00         2956623.00           8.42
```

### Macro-Benchmark

Run the macro-benchmark with:

```bash
nix run .#artifact-eval.macro-benchmark
```

This may take around 1 hour.

**Expected Output:** Once finished, you should be presented with a table similar
to this:

```text
Benchmark            Med w/o SemSan      Med w/ SemSan     Overhead %
pgbench                        2.14               2.23          -4.21
apache                     44292.93           44907.80          -1.39
```

## RQ4: Fuzzing Campaign (Sec 7.4)

```**TODO** I vivecoded this guide. Seems legit to me. Double check.```

This experiment runs a grammar-guided fuzzing campaign against **crun** (an
OCI container runtime) using a LibAFL/Nautilus fuzzer. SemSan is attached in
parallel to surface semantic violations that do not manifest as crashes.

The fuzzer ([case-studies/oci/fuzzer/](case-studies/oci/fuzzer/)) drives crun
via the AFL++ forkserver protocol. A Nautilus grammar
([case-studies/oci/grammar.py](case-studies/oci/grammar.py)) generates
structurally valid OCI `config.json` inputs. The crun source is patched with a
fuzzing harness ([case-studies/oci/0001-crun-add-harness.patch](case-studies/oci/0001-crun-add-harness.patch))
that wraps `libcrun_container_{create,run,kill}` in an `__AFL_LOOP`.

### Setup

**1. Clone crun and apply the harness patch:**

```bash
**TODO: this requires the correct commit, or the patch does not work**
git clone https://github.com/containers/crun case-studies/oci/crun
git -C case-studies/oci/crun am ../0001-crun-add-harness.patch
```

**2. Install crun's build dependencies (Ubuntu):**

```bash
sudo apt-get install -y autoconf automake libtool pkg-config \
    libseccomp-dev libcap-dev libyajl-dev libsystemd-dev
```

**3. Build the AFL++-instrumented crun binary:**

```bash
nix shell .#aflplusplus --command bash -c "
  cd case-studies/oci/crun &&
  ./autogen.sh &&
  CC=afl-clang-lto ./configure &&
  make -j\$(nproc)
"
```

**4. Configure the system for AFL++ (requires root):**

```bash
nix shell .#aflplusplus --command bash -c "
  sudo afl-system-config &&
  echo YES | sudo afl-persistent-config
"
```

**5. Build the LibAFL/Nautilus fuzzer:**

```bash
# Assuming you are still in the Nix shell with `nix develop`
cd case-studies/oci/fuzzer && cargo build --release && cd -
```

### Run

The campaign must run as root because crun creates Linux namespaces and
cgroups. The harness creates and tears down a `rootfs/` directory on each
iteration, so run from a writable working directory.

Start SemSan targeting crun in the background:

```bash
cat > config.yaml <<'EOF'
comm: "crun"
dirOwnership: true
EOF
sudo just run attach &
```

Run the fuzzing campaign from `case-studies/oci/`:

```bash
cd case-studies/oci
sudo ./fuzzer/target/release/forkserver_simple \
    -g grammar.py \
    ./crun/crun @@
```

`@@` is the AFL++ placeholder replaced by the fuzzer with a temp-file path for
each generated input. Crashes are saved to `case-studies/oci/crashes/`.
SemSan violations appear in the terminal running `just run attach`.

Stop the campaign with `Ctrl-C` and SemSan with `sudo kill %1`.

### Coverage

The fuzzer writes AFL-compatible stats to the working directory, updated every
15 seconds:

```bash
# Edge coverage and throughput summary
grep -E 'edges_found|total_execs|execs_per_sec' case-studies/oci/fuzzer_stats

# Full time-series: unix_time, edges_found, corpus_size, execs_per_sec, ...
cat case-studies/oci/plot_data
```

`edges_found` is the number of distinct control-flow edges covered in the
AFL++-instrumented crun binary, and is the primary coverage metric for the
campaign.