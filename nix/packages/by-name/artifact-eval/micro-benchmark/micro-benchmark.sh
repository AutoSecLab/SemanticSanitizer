#!/usr/bin/env bash

set -euo pipefail

if [ ! -f "./semsan-cli" ]; then
  echo "Error: ./semsan-cli not found. Please build semsan-cli first as per the instructions in the README."
  exit 1
fi

if [ ! -f "nix/packages/by-name/artifact-eval/micro-benchmark/config-general.yaml" ]; then
  echo "Error: This script must be run from the root of the repository."
  exit 1
fi

BENCHMARKS=(
  "benchmark-general:nix/packages/by-name/artifact-eval/micro-benchmark/config-general.yaml"
  "benchmark-symlinkmount:nix/packages/by-name/artifact-eval/micro-benchmark/config-symlinkmount.yaml"
  "benchmark-dirownership:nix/packages/by-name/artifact-eval/micro-benchmark/config-dirownership.yaml"
  "benchmark-canary:nix/packages/by-name/artifact-eval/micro-benchmark/config-canary.yaml"
)

declare -A BASELINE_AVG
declare -A SEMSAN_AVG
declare -A OVERHEAD_PCT

extract_average_iterations() {
  local logfile="$1"

  awk '
        /^Iterations:/ {
            sum += $2
            count += 1
        }
        END {
            if (count == 0) {
                exit 1
            }
            printf "%.2f", sum / count
        }
    ' "${logfile}"
}

compute_overhead_pct() {
  local baseline_avg="$1"
  local semsan_avg="$2"

  awk -v baseline="${baseline_avg}" -v semsan="${semsan_avg}" '
        BEGIN {
            if (baseline == 0) {
                print "n/a"
            } else {
                printf "%.2f", ((baseline - semsan) / baseline) * 100
            }
        }
    '
}

run_and_capture() {
  local logfile="$1"
  shift

  "$@" | tee "${logfile}"
}

run_benchmark() {
  local benchmark="$1"
  local config="$2"
  local baseline_log
  local semsan_log
  local baseline_avg
  local semsan_avg
  local overhead_pct
  local semsan_pid

  baseline_log=$(mktemp)
  semsan_log=$(mktemp)

  echo "Running ${benchmark} without SemSan..."
  run_and_capture "${baseline_log}" "${benchmark}"
  baseline_avg=$(extract_average_iterations "${baseline_log}")

  echo "Running ${benchmark} with SemSan..."
  sudo ./semsan-cli attach --config "${config}" &
  semsan_pid=$!

  run_and_capture "${semsan_log}" "${benchmark}"
  semsan_avg=$(extract_average_iterations "${semsan_log}")

  echo "Stopping SemSan..."
  sudo kill "${semsan_pid}"
  wait "${semsan_pid}" 2>/dev/null || true

  rm -f "${baseline_log}" "${semsan_log}"

  overhead_pct=$(compute_overhead_pct "${baseline_avg}" "${semsan_avg}")

  BASELINE_AVG["${benchmark}"]="${baseline_avg}"
  SEMSAN_AVG["${benchmark}"]="${semsan_avg}"
  OVERHEAD_PCT["${benchmark}"]="${overhead_pct}"
}

print_summary_table() {
  local benchmark

  echo
  echo "Summary"
  printf '%-24s %18s %18s %14s\n' "Benchmark" "Avg w/o SemSan" "Avg w/ SemSan" "Overhead %"
  printf '%-24s %18s %18s %14s\n' "---------" "---------------" "-------------" "----------"

  for entry in "${BENCHMARKS[@]}"; do
    benchmark=${entry%%:*}
    printf '%-24s %18s %18s %14s\n' \
      "${benchmark}" \
      "${BASELINE_AVG["${benchmark}"]}" \
      "${SEMSAN_AVG["${benchmark}"]}" \
      "${OVERHEAD_PCT["${benchmark}"]}"
  done
}

for entry in "${BENCHMARKS[@]}"; do
  run_benchmark "${entry%%:*}" "${entry#*:}"
done

print_summary_table
