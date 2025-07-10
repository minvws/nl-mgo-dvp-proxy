#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Initialize submodules if needed
if git submodule status | grep -q '^-' ; then
  make -C "$PROJECT_ROOT" submodules-install
fi

make -C "$PROJECT_ROOT" conf-setup
