#!/bin/bash
# CI script for TOTAL Analyzer
# Usage: ./scripts/ci.sh <path-to-scan> [--sarif]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SCAN_PATH="${1:-$PROJECT_ROOT/examples}"
SARIF_FLAG="${2:-}"

# Check if Docker is available, otherwise use local binary
if command -v docker &> /dev/null; then
    echo "🐳 Running TOTAL Analyzer via Docker"
    docker run --rm -v "$SCAN_PATH":/src ghcr.io/total-protocol/total-analyzer:latest /src $SARIF_FLAG
elif [ -f "$PROJECT_ROOT/target/release/total-analyzer" ]; then
    echo "🦀 Running TOTAL Analyzer from local binary"
    "$PROJECT_ROOT/target/release/total-analyzer" "$SCAN_PATH" $SARIF_FLAG
else
    echo "ERROR: Neither Docker nor local binary found. Build with 'make build' or install Docker."
    exit 1
fi
