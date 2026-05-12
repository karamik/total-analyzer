#!/bin/bash
# TOTAL Analyzer Installer
# Supports: Linux (binary), Docker (any OS), or build from source
# Usage: curl -sSL https://raw.githubusercontent.com/total-protocol/total-analyzer/main/scripts/install.sh | bash

set -euo pipefail

REPO="total-protocol/total-analyzer"
VERSION="v1.0-beta"
GHCR_IMAGE="ghcr.io/total-protocol/total-analyzer"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

detect_os() {
    case "$(uname -s)" in
        Linux*)     OS="linux";;
        Darwin*)    OS="darwin";;
        *)          OS="unknown";;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64)  ARCH="amd64";;
        aarch64) ARCH="arm64";;
        *)       ARCH="unknown";;
    esac
}

install_docker() {
    if command -v docker &> /dev/null; then
        log_info "Docker already installed"
        return
    fi
    log_warn "Docker not found. Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker "$USER"
    log_info "Docker installed. You may need to log out and back in."
}

install_binary() {
    detect_os
    detect_arch
    if [ "$OS" != "linux" ] || [ "$ARCH" != "amd64" ]; then
        log_error "Pre-built binary only available for Linux amd64. Please use Docker or build from source."
    fi
    BINARY_URL="https://github.com/${REPO}/releases/download/${VERSION}/total-analyzer_${OS}_${ARCH}"
    log_info "Downloading binary from $BINARY_URL"
    curl -L -o /tmp/total-analyzer "$BINARY_URL"
    chmod +x /tmp/total-analyzer
    sudo mv /tmp/total-analyzer /usr/local/bin/
    log_info "Binary installed to /usr/local/bin/total-analyzer"
}

install_from_source() {
    log_info "Building from source (requires Rust and Cargo)"
    if ! command -v cargo &> /dev/null; then
        log_error "Rust not installed. Install via https://rustup.rs/"
    fi
    git clone https://github.com/${REPO}.git /tmp/total-analyzer-src
    cd /tmp/total-analyzer-src
    cargo build --release
    sudo cp target/release/total-analyzer /usr/local/bin/
    cd - > /dev/null
    rm -rf /tmp/total-analyzer-src
    log_info "Built and installed from source"
}

main() {
    echo "TOTAL Analyzer Installer"
    echo "========================"
    PS3="Select installation method: "
    options=("Docker (recommended)" "Standalone binary (Linux only)" "Build from source" "Exit")
    select opt in "${options[@]}"; do
        case $opt in
            "Docker (recommended)")
                install_docker
                log_info "Run with: docker run --rm -v \$(pwd):/src $GHCR_IMAGE:$VERSION /src --sarif"
                break
                ;;
            "Standalone binary (Linux only)")
                install_binary
                break
                ;;
            "Build from source")
                install_from_source
                break
                ;;
            "Exit")
                exit 0
                ;;
            *) log_error "Invalid option";;
        esac
    done
    log_info "Installation complete. Try 'total-analyzer --help' or use Docker command above."
}

main "$@"
