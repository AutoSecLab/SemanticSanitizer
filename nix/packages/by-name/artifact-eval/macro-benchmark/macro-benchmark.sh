#!/usr/bin/env bash

set -euo pipefail

if [ ! -f "./semsan-cli" ]; then
  echo "Error: ./semsan-cli not found. Please build semsan-cli first as per the instructions in the README."
  exit 1
fi

if [ ! -f "nix/packages/by-name/artifact-eval/macro-benchmark/config.yaml" ]; then
  echo "Error: This script must be run from the root of the repository."
  exit 1
fi

CONFIG="nix/packages/by-name/artifact-eval/macro-benchmark/config.yaml"
NUM_RUNS=${NUM_RUNS:-9}

PGBENCH_TEST="pts/pgbench"
PGBENCH_PRESET="pts/pgbench.scaling-factor=1000;pts/pgbench.clients=250"

APACHE_TEST="pts/apache"
APACHE_PRESET="pts/apache.concurrent-requests=200"

BENCHMARKS=("pgbench" "apache")

declare -A BENCHMARK_TEST
BENCHMARK_TEST["pgbench"]="${PGBENCH_TEST}"
BENCHMARK_TEST["apache"]="${APACHE_TEST}"

declare -A BENCHMARK_PRESET
BENCHMARK_PRESET["pgbench"]="${PGBENCH_PRESET}"
BENCHMARK_PRESET["apache"]="${APACHE_PRESET}"

declare -A BASELINE_MED
declare -A SEMSAN_MED
declare -A OVERHEAD_PCT

setup_phoronix() {
  local pts_dir="${PTS_USER_PATH_OVERRIDE:-$HOME/.phoronix-test-suite}"
  mkdir -p "${pts_dir}"

  cat > "${pts_dir}/user-config.xml" <<'PTSEOF'
<?xml version="1.0"?>
<PhoronixTestSuite>
  <Options>
    <OpenBrowser>FALSE</OpenBrowser>
    <DefaultBrowser></DefaultBrowser>
    <WatchTestRunOutput>FALSE</WatchTestRunOutput>
  </Options>
  <BatchMode>
    <SaveResults>FALSE</SaveResults>
    <OpenBrowser>FALSE</OpenBrowser>
    <UploadResults>FALSE</UploadResults>
    <PromptForTestIdentifier>FALSE</PromptForTestIdentifier>
    <PromptForTestDescription>FALSE</PromptForTestDescription>
    <PromptSaveName>FALSE</PromptSaveName>
    <RunAllTestCombinations>TRUE</RunAllTestCombinations>
    <Configured>TRUE</Configured>
  </BatchMode>
</PhoronixTestSuite>
PTSEOF
}

run_pts_test() {
  local logfile="$1"
  local test="$2"
  local preset="$3"

  PRESET_OPTIONS="${preset}" \
    stdbuf -oL phoronix-test-suite batch-run "${test}" 2>&1 | tee "${logfile}"
}

extract_result() {
  local logfile="$1"

  awk '/Average:/ { print $2 }' "${logfile}" | tail -1
}

compute_median() {
  local values_file="$1"

  sort -n "${values_file}" | awk '{vals[NR]=$1} END {
    if (NR == 0) { print "n/a"; exit }
    if (NR % 2 == 1) printf "%.2f", vals[(NR+1)/2]
    else printf "%.2f", (vals[NR/2] + vals[NR/2+1]) / 2
  }'
}

compute_overhead_pct() {
  local baseline_med="$1"
  local semsan_med="$2"

  awk -v baseline="${baseline_med}" -v semsan="${semsan_med}" '
    BEGIN {
      if (baseline == 0) {
        print "n/a"
      } else {
        printf "%.2f", ((baseline - semsan) / baseline) * 100
      }
    }
  '
}

run_benchmark() {
  local name="$1"
  local test="$2"
  local preset="$3"
  local baseline_values semsan_values logfile result semsan_pid

  baseline_values=$(mktemp)
  semsan_values=$(mktemp)

  echo "=== Benchmark: ${name} ==="

  echo "Running ${name} without SemSan (${NUM_RUNS} runs)..."
  for i in $(seq 1 "${NUM_RUNS}"); do
    echo "  Run ${i}/${NUM_RUNS}..."
    logfile=$(mktemp)
    run_pts_test "${logfile}" "${test}" "${preset}"
    result=$(extract_result "${logfile}")
    echo "${result}" >> "${baseline_values}"
    echo "  Result: ${result}"
    rm -f "${logfile}"
  done

  echo "Running ${name} with SemSan (${NUM_RUNS} runs)..."
  sudo ./semsan-cli attach --config "${CONFIG}" &
  semsan_pid=$!
  sleep 2

  for i in $(seq 1 "${NUM_RUNS}"); do
    echo "  Run ${i}/${NUM_RUNS}..."
    logfile=$(mktemp)
    run_pts_test "${logfile}" "${test}" "${preset}"
    result=$(extract_result "${logfile}")
    echo "${result}" >> "${semsan_values}"
    echo "  Result: ${result}"
    rm -f "${logfile}"
  done

  echo "Stopping SemSan..."
  sudo kill "${semsan_pid}"
  wait "${semsan_pid}" 2>/dev/null || true

  BASELINE_MED["${name}"]=$(compute_median "${baseline_values}")
  SEMSAN_MED["${name}"]=$(compute_median "${semsan_values}")
  OVERHEAD_PCT["${name}"]=$(compute_overhead_pct "${BASELINE_MED["${name}"]}" "${SEMSAN_MED["${name}"]}")

  rm -f "${baseline_values}" "${semsan_values}"
}

print_summary_table() {
  echo
  echo "Summary"
  printf '%-16s %18s %18s %14s\n' "Benchmark" "Med w/o SemSan" "Med w/ SemSan" "Overhead %"
  printf '%-16s %18s %18s %14s\n' "---------" "---------------" "-------------" "----------"

  for bench in "${BENCHMARKS[@]}"; do
    printf '%-16s %18s %18s %14s\n' \
      "${bench}" \
      "${BASELINE_MED["${bench}"]}" \
      "${SEMSAN_MED["${bench}"]}" \
      "${OVERHEAD_PCT["${bench}"]}"
  done
}

setup_phoronix

echo "Installing phoronix tests..."
phoronix-test-suite install "${PGBENCH_TEST}" "${APACHE_TEST}"

for bench in "${BENCHMARKS[@]}"; do
  run_benchmark "${bench}" "${BENCHMARK_TEST["${bench}"]}" "${BENCHMARK_PRESET["${bench}"]}"
done

print_summary_table
