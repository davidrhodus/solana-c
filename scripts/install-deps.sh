#!/bin/bash
#
# install-deps.sh - Install Solana C validator dependencies
#
# This script installs all required dependencies for building the validator
# with full functionality (RocksDB persistent storage, QUIC transport).
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        if command -v brew &>/dev/null; then
            PKG_MGR="brew"
        else
            log_error "Homebrew not found. Install from https://brew.sh"
            exit 1
        fi
    elif [[ -f /etc/debian_version ]]; then
        OS="debian"
        PKG_MGR="apt"
    elif [[ -f /etc/redhat-release ]]; then
        OS="redhat"
        PKG_MGR="dnf"
    else
        log_error "Unsupported OS: $OSTYPE"
        exit 1
    fi
    log_info "Detected OS: $OS (package manager: $PKG_MGR)"
}

# Install basic build tools
install_build_tools() {
    log_step "Installing build tools..."

    case $PKG_MGR in
        brew)
            brew install cmake pkg-config
            ;;
        apt)
            sudo apt update
            sudo apt install -y build-essential cmake pkg-config git
            ;;
        dnf)
            sudo dnf install -y cmake gcc gcc-c++ make pkg-config git
            ;;
    esac
}

# Install libsodium
install_libsodium() {
    log_step "Installing libsodium..."

    case $PKG_MGR in
        brew)
            brew install libsodium
            ;;
        apt)
            sudo apt install -y libsodium-dev
            ;;
        dnf)
            sudo dnf install -y libsodium-devel
            ;;
    esac
}

# Install OpenSSL
install_openssl() {
    log_step "Installing OpenSSL..."

    case $PKG_MGR in
        brew)
            brew install openssl@3
            # Add to PKG_CONFIG_PATH for CMake
            export PKG_CONFIG_PATH="/opt/homebrew/opt/openssl@3/lib/pkgconfig:$PKG_CONFIG_PATH"
            ;;
        apt)
            sudo apt install -y libssl-dev
            ;;
        dnf)
            sudo dnf install -y openssl-devel
            ;;
    esac
}

# Install compression libraries
install_compression() {
    log_step "Installing compression libraries (zstd, lz4)..."

    case $PKG_MGR in
        brew)
            brew install zstd lz4
            ;;
        apt)
            sudo apt install -y libzstd-dev liblz4-dev
            ;;
        dnf)
            sudo dnf install -y libzstd-devel lz4-devel
            ;;
    esac
}

# Install RocksDB
install_rocksdb() {
    log_step "Installing RocksDB..."

    case $PKG_MGR in
        brew)
            brew install rocksdb
            ;;
        apt)
            # Check Ubuntu version for package availability
            if apt-cache show librocksdb-dev &>/dev/null; then
                sudo apt install -y librocksdb-dev
            else
                log_warn "librocksdb-dev not in apt, building from source..."
                install_rocksdb_source
            fi
            ;;
        dnf)
            sudo dnf install -y rocksdb-devel || install_rocksdb_source
            ;;
    esac
}

# Build RocksDB from source (fallback)
install_rocksdb_source() {
    log_step "Building RocksDB from source..."

    local ROCKSDB_VERSION="8.10.0"
    local BUILD_DIR="/tmp/rocksdb-build"

    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    curl -L "https://github.com/facebook/rocksdb/archive/refs/tags/v${ROCKSDB_VERSION}.tar.gz" | tar xz
    cd "rocksdb-${ROCKSDB_VERSION}"

    # Build shared library
    make shared_lib -j$(nproc || sysctl -n hw.ncpu)

    # Install
    sudo make install-shared INSTALL_PATH=/usr/local
    sudo ldconfig 2>/dev/null || true

    cd /
    rm -rf "$BUILD_DIR"

    log_info "RocksDB ${ROCKSDB_VERSION} installed to /usr/local"
}

# Install Rust (needed for quiche)
install_rust() {
    if command -v cargo &>/dev/null; then
        log_info "Rust already installed: $(rustc --version)"
        return
    fi

    log_step "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
}

# Build and install quiche
install_quiche() {
    log_step "Building quiche from source..."

    # Ensure Rust is available
    install_rust
    source "$HOME/.cargo/env" 2>/dev/null || true

    local QUICHE_VERSION="0.22.0"
    local BUILD_DIR="/tmp/quiche-build"

    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    # Clone quiche
    git clone --branch "${QUICHE_VERSION}" --depth 1 https://github.com/cloudflare/quiche.git
    cd quiche

    # quiche depends on submodules (e.g. BoringSSL) for the FFI build.
    git submodule update --init --recursive --depth 1 || git submodule update --init --recursive

    # Build with FFI support
    cargo build --release --features ffi

    # Install library
    sudo mkdir -p /usr/local/lib /usr/local/include
    sudo cp target/release/libquiche.so /usr/local/lib/ 2>/dev/null || \
    sudo cp target/release/libquiche.dylib /usr/local/lib/ 2>/dev/null || \
    sudo cp target/release/libquiche.a /usr/local/lib/

    # Install header
    sudo cp quiche/include/quiche.h /usr/local/include/

    # Update library cache
    sudo ldconfig 2>/dev/null || true

    cd /
    rm -rf "$BUILD_DIR"

    log_info "quiche ${QUICHE_VERSION} installed to /usr/local"
}

# Install jemalloc (optional but recommended)
install_jemalloc() {
    log_step "Installing jemalloc (optional)..."

    case $PKG_MGR in
        brew)
            brew install jemalloc
            ;;
        apt)
            sudo apt install -y libjemalloc-dev
            ;;
        dnf)
            sudo dnf install -y jemalloc-devel
            ;;
    esac
}

# Verify installations
verify_deps() {
    log_step "Verifying installations..."

    local status=0

    # Check pkg-config packages
    for pkg in libsodium openssl zstd liblz4; do
        if pkg-config --exists "$pkg" 2>/dev/null; then
            log_info "  $pkg: $(pkg-config --modversion $pkg)"
        else
            log_warn "  $pkg: not found via pkg-config"
        fi
    done

    # Check RocksDB
    if pkg-config --exists rocksdb 2>/dev/null; then
        log_info "  rocksdb: $(pkg-config --modversion rocksdb)"
    elif [[ -f /usr/local/include/rocksdb/c.h ]]; then
        log_info "  rocksdb: installed (manual)"
    else
        log_warn "  rocksdb: NOT FOUND"
        status=1
    fi

    # Check quiche
    if [[ -f /usr/local/include/quiche.h ]]; then
        log_info "  quiche: installed"
    else
        log_warn "  quiche: NOT FOUND"
        status=1
    fi

    return $status
}

# Print build instructions
print_instructions() {
    echo ""
    echo "========================================"
    echo "Dependencies installed successfully!"
    echo "========================================"
    echo ""
    echo "To build the validator:"
    echo ""
    echo "  cd /path/to/solana-c/build"
    echo "  cmake .."
    echo "  make -j\$(nproc)"
    echo ""
    echo "Expected output should include:"
    echo "  - Storage backend: RocksDB enabled"
    echo "  - QUIC transport: enabled (quiche)"
    echo ""

    if [[ "$OS" == "macos" ]]; then
        echo "Note: On macOS, you may need to set:"
        echo "  export PKG_CONFIG_PATH=\"/opt/homebrew/opt/openssl@3/lib/pkgconfig:\$PKG_CONFIG_PATH\""
        echo ""
    fi
}

# Main
main() {
    echo "========================================"
    echo "Solana C Validator - Dependency Installer"
    echo "========================================"
    echo ""

    detect_os

    install_build_tools
    install_libsodium
    install_openssl
    install_compression
    install_rocksdb
    install_quiche
    install_jemalloc

    echo ""
    if verify_deps; then
        print_instructions
    else
        log_error "Some dependencies are missing. Check the output above."
        exit 1
    fi
}

# Handle arguments
case "${1:-}" in
    --rocksdb-only)
        detect_os
        install_rocksdb
        ;;
    --quiche-only)
        detect_os
        install_quiche
        ;;
    --verify)
        detect_os
        verify_deps
        ;;
    --help|-h)
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --rocksdb-only  Install only RocksDB"
        echo "  --quiche-only   Install only quiche"
        echo "  --verify        Verify installed dependencies"
        echo "  --help          Show this help"
        echo ""
        echo "Without options, installs all dependencies."
        ;;
    *)
        main
        ;;
esac
