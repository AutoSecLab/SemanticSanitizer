#!/usr/bin/env bash

set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "This script must be run as root." >&2
  exit 1
fi

DIAGNOSTIC_PORT="${DIAGNOSTIC_PORT:-8080}"

echo "Disabling protected links.."
sysctl fs.protected_symlinks=0
sysctl fs.protected_regular=0

echo "Enabling diagnostic server on port ${DIAGNOSTIC_PORT}.."
install -m 0755 -d /etc/docker

python3 - "${DIAGNOSTIC_PORT}" <<'PY'
import json
import os
import sys

port = int(sys.argv[1])
path = "/etc/docker/daemon.json"

if os.path.exists(path) and os.path.getsize(path) > 0:
    with open(path, encoding="utf-8") as f:
        config = json.load(f)
else:
    config = {}

config["network-diagnostic-port"] = port

with open(path, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2, sort_keys=True)
    f.write("\n")
PY

echo "Reloading Docker configuration.."
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet docker; then
  systemctl reload docker
else
  dockerd_pid="$(pgrep -x dockerd | head -n1 || true)"
  if [[ -z ${dockerd_pid} ]]; then
    echo "dockerd is not running; start Docker to enable the diagnostic server." >&2
    exit 1
  fi
  kill -HUP "${dockerd_pid}"
fi

echo "Diagnostic server enabled on port ${DIAGNOSTIC_PORT}."