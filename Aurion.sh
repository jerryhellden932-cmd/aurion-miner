#!/usr/bin/env bash
set -eu
cd -- "$(dirname -- "$0")"
if ! command -v python3 >/dev/null 2>&1; then
  echo "Install Python 3.10+ from python.org first."
  exit 1
fi
exec python3 launcher.py "$@"
