#!/bin/bash
#
# fetch_fixtures.sh - Download Firedancer conformance test fixtures
#
# Usage: ./fetch_fixtures.sh [output_dir]
#

set -e

OUTPUT_DIR="${1:-./tests/conformance/fixtures}"

echo "Fetching Firedancer conformance fixtures..."

# Create output directories
mkdir -p "$OUTPUT_DIR/txn"
mkdir -p "$OUTPUT_DIR/syscall"
mkdir -p "$OUTPUT_DIR/shred"
mkdir -p "$OUTPUT_DIR/serialize"
mkdir -p "$OUTPUT_DIR/bpf"

# Check if git is available
if ! command -v git &> /dev/null; then
    echo "Error: git is required but not installed"
    exit 1
fi

# Clone Firedancer conformance repo (shallow clone for speed)
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "Cloning Firedancer conformance repository..."
git clone --depth 1 https://github.com/firedancer-io/firedancer-conformance.git "$TEMP_DIR/conformance" 2>/dev/null || {
    echo "Warning: Could not clone Firedancer conformance repo."
    echo "Creating placeholder fixtures for basic testing..."

    # Create placeholder for manual testing
    cat > "$OUTPUT_DIR/README.md" << 'EOF'
# Conformance Test Fixtures

This directory should contain conformance test fixtures.

## Obtaining Fixtures

### From Firedancer
```bash
git clone https://github.com/firedancer-io/firedancer-conformance.git
cp -r firedancer-conformance/fixtures/* ./
```

### Creating Custom Fixtures

Fixtures are pairs of files:
- `<test_name>.input` - Protobuf-encoded input
- `<test_name>.output` - Expected protobuf-encoded output

The protobuf schemas are defined in the Firedancer conformance repository.

## Fixture Format

### Transaction Execution (txn/)
Input: TxnContext protobuf containing:
- Transaction bytes
- Account states
- Slot context

Output: TxnResult protobuf containing:
- Updated account states
- Return data
- Logs
- Compute units consumed

### Shred Parsing (shred/)
Input: Raw shred bytes
Output: Parsed shred structure

### Serialization (serialize/)
Input: Structured data
Output: Bincode-serialized bytes
EOF

    echo "Created $OUTPUT_DIR/README.md with instructions"
    exit 0
}

# Copy fixtures
echo "Copying fixtures..."
if [ -d "$TEMP_DIR/conformance/fixtures" ]; then
    cp -r "$TEMP_DIR/conformance/fixtures/"* "$OUTPUT_DIR/" 2>/dev/null || true
fi

# Count fixtures
FIXTURE_COUNT=$(find "$OUTPUT_DIR" -name "*.input" 2>/dev/null | wc -l | tr -d ' ')
echo "Fetched $FIXTURE_COUNT fixture(s)"

if [ "$FIXTURE_COUNT" -eq "0" ]; then
    echo "Warning: No fixtures found. Creating placeholder..."
    cat > "$OUTPUT_DIR/README.md" << 'EOF'
# Conformance Test Fixtures

No fixtures were found in the Firedancer conformance repository.
Please check if the repository structure has changed.

## Creating Custom Fixtures

See the conformance.h header for fixture format documentation.
EOF
fi

echo "Done. Fixtures in: $OUTPUT_DIR"
