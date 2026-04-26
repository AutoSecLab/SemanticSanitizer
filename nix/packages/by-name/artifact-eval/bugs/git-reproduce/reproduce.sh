#!/usr/bin/env bash

set -euo pipefail

if [ ! -f "./semsan-cli" ]; then
  echo "Error: ./semsan-cli not found. Please build semsan-cli first as per the instructions in the README."
  exit 1
fi
cli="$(realpath ./semsan-cli)"

if [ ! -f "nix/packages/by-name/artifact-eval/micro-benchmark/config-general.yaml" ]; then
  echo "Error: This script must be run from the root of the repository."
  exit 1
fi

repo_root="$(pwd)"
gitweb_dir="${repo_root}/.git/gitweb"

# Clean up stale git-instaweb/lighttpd state from previous runs. Otherwise a
# fresh repro may fail to bind to port 1234 and the trigger will hit an old
# server instance instead.
sudo @VULN@/bin/git instaweb --stop >/dev/null 2>&1 || true
while IFS= read -r pid; do
  [ -n "$pid" ] || continue
  sudo kill "$pid" >/dev/null 2>&1 || true
done < <(sudo pgrep -f "$gitweb_dir" 2>/dev/null || true)
sudo rm -rf "$gitweb_dir/lighttpd" "$gitweb_dir/httpd.conf" "$gitweb_dir/pid" >/dev/null 2>&1 || true

sudo mprocs '@VULN@/bin/git instaweb' "${cli} attach --config @CONFIG@"
