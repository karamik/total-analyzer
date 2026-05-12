#!/bin/bash
set -e

REPO="total-protocol/total-analyzer"
VERSION="v1.0-beta"

echo "Downloading TOTAL Analyzer ${VERSION}..."

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [ "$OS" != "linux" ]; then
    echo "Pre-built binary only available for Linux. Use Docker instead."
    exit 1
fi

if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ]; then
    ARCH="arm64"
fi

BINARY_URL="https://github.com/${REPO}/releases/download/${VERSION}/total-analyzer_${OS}_${ARCH}"

curl -L -o total-analyzer "$BINARY_URL"
chmod +x total-analyzer
sudo mv total-analyzer /usr/local/bin/

echo "Installed. Run 'total-analyzer --help'"
