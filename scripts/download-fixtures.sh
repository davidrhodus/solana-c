#!/bin/bash
#
# download-fixtures.sh - Download Firedancer conformance test fixtures
#
# Downloads test fixtures from the solana-conformance repository.
# These fixtures are used to verify our implementation against Firedancer.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FIXTURES_DIR="${PROJECT_ROOT}/fixtures"
CACHE_DIR="${HOME}/.cache/solana-conformance"

# Conformance fixture sources
CONFORMANCE_REPO="https://github.com/firedancer-io/solana-conformance"
FIXTURES_RELEASE="https://github.com/firedancer-io/test-vectors/releases/latest/download"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for required tools
check_deps() {
    local missing=0

    for cmd in curl tar unzip; do
        if ! command -v $cmd &> /dev/null; then
            log_error "Required command not found: $cmd"
            missing=1
        fi
    done

    if [ $missing -eq 1 ]; then
        log_error "Please install missing dependencies and try again"
        exit 1
    fi
}

# Download fixtures from test-vectors repository
download_test_vectors() {
    log_info "Downloading Firedancer test vectors..."

    mkdir -p "$CACHE_DIR"
    mkdir -p "$FIXTURES_DIR"

    # Download test vector archive
    local archive="$CACHE_DIR/test-vectors.tar.gz"

    if [ ! -f "$archive" ] || [ "$FORCE_DOWNLOAD" = "1" ]; then
        log_info "Fetching test vectors archive..."

        # Try to download from releases
        if curl -fsSL -o "$archive" \
            "https://github.com/firedancer-io/test-vectors/archive/refs/heads/main.tar.gz" 2>/dev/null; then
            log_info "Downloaded test vectors from GitHub"
        else
            log_warn "Could not download test vectors automatically"
            log_info "Generating minimal test fixtures locally..."
            generate_local_fixtures
            return
        fi
    else
        log_info "Using cached test vectors"
    fi

    # Extract fixtures
    log_info "Extracting fixtures..."
    cd "$CACHE_DIR"
    tar -xzf "$archive"

    # Move fixtures to project
    if [ -d "test-vectors-main/instr/fixtures" ]; then
        cp -r test-vectors-main/instr/fixtures/* "$FIXTURES_DIR/" 2>/dev/null || true
    fi

    # Organize fixtures by component
    organize_fixtures

    log_info "Fixtures downloaded to: $FIXTURES_DIR"
}

# Generate minimal local fixtures for testing
generate_local_fixtures() {
    log_info "Generating minimal test fixtures..."

    mkdir -p "$FIXTURES_DIR/txn"
    mkdir -p "$FIXTURES_DIR/bpf"
    mkdir -p "$FIXTURES_DIR/syscall"
    mkdir -p "$FIXTURES_DIR/shred"
    mkdir -p "$FIXTURES_DIR/serialize"

    # Create a simple test fixture marker
    echo "# Minimal local fixtures" > "$FIXTURES_DIR/README.md"
    echo "# Download full fixtures from: $CONFORMANCE_REPO" >> "$FIXTURES_DIR/README.md"
    echo "" >> "$FIXTURES_DIR/README.md"
    echo "These are minimal test fixtures generated locally." >> "$FIXTURES_DIR/README.md"
    echo "For comprehensive testing, download the full Firedancer test vectors:" >> "$FIXTURES_DIR/README.md"
    echo "" >> "$FIXTURES_DIR/README.md"
    echo "  git clone $CONFORMANCE_REPO" >> "$FIXTURES_DIR/README.md"
    echo "  # Follow setup instructions in the repository" >> "$FIXTURES_DIR/README.md"

    log_info "Minimal fixtures created at: $FIXTURES_DIR"
    log_warn "For comprehensive testing, download full Firedancer fixtures manually"
}

# Organize fixtures by test component
organize_fixtures() {
    log_info "Organizing fixtures..."

    # Create component directories if they don't exist
    mkdir -p "$FIXTURES_DIR/txn"
    mkdir -p "$FIXTURES_DIR/bpf"
    mkdir -p "$FIXTURES_DIR/syscall"
    mkdir -p "$FIXTURES_DIR/shred"
    mkdir -p "$FIXTURES_DIR/serialize"

    # Move fixtures to appropriate directories based on content
    # (The exact organization depends on how Firedancer structures their fixtures)

    # System program fixtures -> txn
    if [ -d "$FIXTURES_DIR/system" ]; then
        mv "$FIXTURES_DIR/system"/* "$FIXTURES_DIR/txn/" 2>/dev/null || true
        rmdir "$FIXTURES_DIR/system" 2>/dev/null || true
    fi

    # Vote program fixtures -> txn
    if [ -d "$FIXTURES_DIR/vote" ]; then
        mv "$FIXTURES_DIR/vote"/* "$FIXTURES_DIR/txn/" 2>/dev/null || true
        rmdir "$FIXTURES_DIR/vote" 2>/dev/null || true
    fi

    # Stake program fixtures -> txn
    if [ -d "$FIXTURES_DIR/stake" ]; then
        mv "$FIXTURES_DIR/stake"/* "$FIXTURES_DIR/txn/" 2>/dev/null || true
        rmdir "$FIXTURES_DIR/stake" 2>/dev/null || true
    fi

    # BPF loader fixtures -> bpf
    if [ -d "$FIXTURES_DIR/bpf_loader" ]; then
        mv "$FIXTURES_DIR/bpf_loader"/* "$FIXTURES_DIR/bpf/" 2>/dev/null || true
        rmdir "$FIXTURES_DIR/bpf_loader" 2>/dev/null || true
    fi

    # Count fixtures
    local count=$(find "$FIXTURES_DIR" -name "*.fix" 2>/dev/null | wc -l)
    log_info "Found $count fixture files"
}

# Clone and set up the conformance tool
setup_conformance_tool() {
    log_info "Setting up solana-conformance tool..."

    local conformance_dir="$CACHE_DIR/solana-conformance"

    if [ -d "$conformance_dir" ]; then
        log_info "Updating existing conformance repository..."
        cd "$conformance_dir"
        git pull --quiet
    else
        log_info "Cloning conformance repository..."
        git clone --quiet "$CONFORMANCE_REPO" "$conformance_dir"
    fi

    # Check if we can run the tool
    cd "$conformance_dir"

    if [ -f "requirements.txt" ]; then
        log_info "Installing Python dependencies..."

        # Create virtual environment if needed
        if [ ! -d "venv" ]; then
            python3 -m venv venv
        fi

        source venv/bin/activate
        pip install --quiet -r requirements.txt

        log_info "Conformance tool set up at: $conformance_dir"
    fi
}

# Print usage
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -f, --force     Force re-download even if cached"
    echo "  -t, --tool      Also set up solana-conformance tool"
    echo "  -h, --help      Show this help"
    echo ""
    echo "This script downloads Firedancer conformance test fixtures"
    echo "to enable testing our Solana implementation against Firedancer."
}

# Main
main() {
    FORCE_DOWNLOAD=0
    SETUP_TOOL=0

    while [ $# -gt 0 ]; do
        case "$1" in
            -f|--force)
                FORCE_DOWNLOAD=1
                ;;
            -t|--tool)
                SETUP_TOOL=1
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done

    log_info "Firedancer Conformance Fixture Downloader"
    log_info "Project root: $PROJECT_ROOT"

    check_deps
    download_test_vectors

    if [ "$SETUP_TOOL" = "1" ]; then
        setup_conformance_tool
    fi

    log_info "Done!"
    echo ""
    echo "To run conformance tests:"
    echo "  cd $PROJECT_ROOT/build"
    echo "  ./bin/test_conformance $FIXTURES_DIR"
    echo ""
    echo "Or use the Python runner:"
    echo "  python3 run_conformance.py $FIXTURES_DIR"
}

main "$@"
