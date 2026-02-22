#!/bin/bash
#
# build-quiche.sh - Build and install quiche QUIC library
#
# This script builds quiche from source and installs it to /usr/local
# for use with the Solana C validator's QUIC transport.
#

set -e

# Configuration
QUICHE_VERSION="${QUICHE_VERSION:-0.22.0}"
INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
BUILD_DIR="${BUILD_DIR:-/tmp/quiche-build}"
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

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

# Check for Rust
check_rust() {
    if ! command -v cargo &>/dev/null; then
        log_error "Rust/Cargo not found."
        echo ""
        echo "Install Rust with:"
        echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        echo ""
        exit 1
    fi
    log_info "Rust version: $(rustc --version)"
    log_info "Cargo version: $(cargo --version)"
}

# Check for required tools
check_tools() {
    local missing=""

    for tool in git cmake; do
        if ! command -v "$tool" &>/dev/null; then
            missing="$missing $tool"
        fi
    done

    if [[ -n "$missing" ]]; then
        log_error "Missing required tools:$missing"
        exit 1
    fi
}

# Clone quiche repository
clone_quiche() {
    log_step "Cloning quiche v${QUICHE_VERSION}..."

    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    git clone --branch "${QUICHE_VERSION}" --depth 1 \
        https://github.com/cloudflare/quiche.git

    cd quiche

    # quiche depends on submodules (e.g. BoringSSL) for the FFI build.
    log_step "Initializing quiche submodules..."
    if ! git submodule update --init --recursive --depth 1; then
        git submodule update --init --recursive
    fi
    log_info "Cloned to: $(pwd)"
}

# Build quiche
build_quiche() {
    log_step "Building quiche with FFI support..."

    cd "$BUILD_DIR/quiche"

    # Build release with FFI bindings
    RUSTFLAGS="-C target-cpu=native" cargo build --release --features ffi -j"$JOBS"

    log_info "Build complete"
}

# Install quiche
install_quiche() {
    log_step "Installing quiche to ${INSTALL_PREFIX}..."

    cd "$BUILD_DIR/quiche"

    # Create directories
    sudo mkdir -p "${INSTALL_PREFIX}/lib"
    sudo mkdir -p "${INSTALL_PREFIX}/include"
    sudo mkdir -p "${INSTALL_PREFIX}/lib/pkgconfig"

    # Find and install library
    local lib_name=""
    if [[ -f target/release/libquiche.so ]]; then
        lib_name="libquiche.so"
        sudo cp target/release/libquiche.so "${INSTALL_PREFIX}/lib/"
        # Create symlinks for versioned library
        sudo ln -sf libquiche.so "${INSTALL_PREFIX}/lib/libquiche.so.0"
    elif [[ -f target/release/libquiche.dylib ]]; then
        lib_name="libquiche.dylib"
        sudo cp target/release/libquiche.dylib "${INSTALL_PREFIX}/lib/"
    elif [[ -f target/release/libquiche.a ]]; then
        lib_name="libquiche.a"
        sudo cp target/release/libquiche.a "${INSTALL_PREFIX}/lib/"
    else
        log_error "No library found in target/release/"
        ls -la target/release/
        exit 1
    fi

    log_info "Installed library: $lib_name"

    # Install header
    sudo cp quiche/include/quiche.h "${INSTALL_PREFIX}/include/"
    log_info "Installed header: quiche.h"

    # Create pkg-config file
    cat << EOF | sudo tee "${INSTALL_PREFIX}/lib/pkgconfig/quiche.pc" > /dev/null
prefix=${INSTALL_PREFIX}
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include

Name: quiche
Description: QUIC transport protocol library
Version: ${QUICHE_VERSION}
Libs: -L\${libdir} -lquiche
Cflags: -I\${includedir}
EOF

    log_info "Created pkg-config file: quiche.pc"

    # Update library cache (Linux only)
    if command -v ldconfig &>/dev/null; then
        sudo ldconfig
        log_info "Updated library cache"
    fi
}

# Verify installation
verify_install() {
    log_step "Verifying installation..."

    local errors=0

    # Check header
    if [[ -f "${INSTALL_PREFIX}/include/quiche.h" ]]; then
        log_info "  Header: ${INSTALL_PREFIX}/include/quiche.h"
    else
        log_error "  Header not found!"
        ((errors++))
    fi

    # Check library
    local lib_found=0
    for ext in so dylib a; do
        if [[ -f "${INSTALL_PREFIX}/lib/libquiche.${ext}" ]]; then
            log_info "  Library: ${INSTALL_PREFIX}/lib/libquiche.${ext}"
            lib_found=1
            break
        fi
    done
    if [[ $lib_found -eq 0 ]]; then
        log_error "  Library not found!"
        ((errors++))
    fi

    # Check pkg-config
    if pkg-config --exists quiche 2>/dev/null; then
        log_info "  pkg-config: $(pkg-config --modversion quiche)"
    else
        log_warn "  pkg-config: not configured (may need PKG_CONFIG_PATH)"
    fi

    if [[ $errors -gt 0 ]]; then
        return 1
    fi

    return 0
}

# Cleanup
cleanup() {
    log_step "Cleaning up build directory..."
    rm -rf "$BUILD_DIR"
    log_info "Cleanup complete"
}

# Test compilation
test_compile() {
    log_step "Testing compilation with quiche..."

    local test_file="/tmp/quiche_test.c"
    local test_bin="/tmp/quiche_test"

    cat > "$test_file" << 'EOF'
#include <quiche.h>
#include <stdio.h>

int main() {
    printf("quiche version: %s\n", quiche_version());
    return 0;
}
EOF

    local cc="${CC:-cc}"
    local cflags="-I${INSTALL_PREFIX}/include"
    local ldflags="-L${INSTALL_PREFIX}/lib -lquiche"

    if $cc $cflags "$test_file" $ldflags -o "$test_bin" 2>/dev/null; then
        log_info "  Compilation: OK"

        # Try to run (may fail without LD_LIBRARY_PATH on Linux)
        if LD_LIBRARY_PATH="${INSTALL_PREFIX}/lib:$LD_LIBRARY_PATH" \
           DYLD_LIBRARY_PATH="${INSTALL_PREFIX}/lib:$DYLD_LIBRARY_PATH" \
           "$test_bin" 2>/dev/null; then
            log_info "  Execution: OK"
        else
            log_warn "  Execution: Failed (may need LD_LIBRARY_PATH)"
        fi

        rm -f "$test_bin"
    else
        log_error "  Compilation: FAILED"
        rm -f "$test_file"
        return 1
    fi

    rm -f "$test_file"
    return 0
}

# Print usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Build and install quiche QUIC library from source."
    echo ""
    echo "Options:"
    echo "  --version VER     quiche version to build (default: ${QUICHE_VERSION})"
    echo "  --prefix PATH     Installation prefix (default: ${INSTALL_PREFIX})"
    echo "  --jobs N          Parallel build jobs (default: auto)"
    echo "  --no-cleanup      Don't remove build directory"
    echo "  --verify-only     Only verify existing installation"
    echo "  --help            Show this help"
    echo ""
    echo "Environment variables:"
    echo "  QUICHE_VERSION    Same as --version"
    echo "  INSTALL_PREFIX    Same as --prefix"
    echo "  JOBS              Same as --jobs"
    echo ""
}

# Main
main() {
    local do_cleanup=1
    local verify_only=0

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --version)
                QUICHE_VERSION="$2"
                shift 2
                ;;
            --prefix)
                INSTALL_PREFIX="$2"
                shift 2
                ;;
            --jobs)
                JOBS="$2"
                shift 2
                ;;
            --no-cleanup)
                do_cleanup=0
                shift
                ;;
            --verify-only)
                verify_only=1
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    echo "========================================"
    echo "quiche QUIC Library Builder"
    echo "========================================"
    echo ""
    echo "Version:    ${QUICHE_VERSION}"
    echo "Prefix:     ${INSTALL_PREFIX}"
    echo "Jobs:       ${JOBS}"
    echo ""

    if [[ $verify_only -eq 1 ]]; then
        verify_install
        test_compile
        exit $?
    fi

    check_rust
    check_tools
    clone_quiche
    build_quiche
    install_quiche

    if verify_install && test_compile; then
        [[ $do_cleanup -eq 1 ]] && cleanup
        echo ""
        echo "========================================"
        echo "quiche ${QUICHE_VERSION} installed successfully!"
        echo "========================================"
        echo ""
        echo "Add to your CMake build:"
        echo "  cmake -DCMAKE_PREFIX_PATH=${INSTALL_PREFIX} .."
        echo ""
    else
        log_error "Installation verification failed!"
        exit 1
    fi
}

main "$@"
