# Firedancer Conformance Test Fixtures

This directory holds conformance test fixtures for validating our Solana implementation
against Firedancer's test vectors.

## Quick Start

Run the download script to fetch fixtures:

```bash
./scripts/download-fixtures.sh
```

Or manually download from the Firedancer test vectors repository.

## Manual Download

1. Clone the test vectors repository:
   ```bash
   git clone https://github.com/firedancer-io/test-vectors.git
   ```

2. Copy the fixtures to this directory:
   ```bash
   cp -r test-vectors/instr/fixtures/* ./fixtures/
   ```

## Fixture Format

Fixtures are binary files using Firedancer's protobuf schema:
- `<test_name>.input` - Input data (InstrContext protobuf)
- `<test_name>.output` - Expected output (InstrEffects protobuf)

## Directory Structure

```
fixtures/
├── txn/          # Transaction execution tests
├── bpf/          # BPF VM execution tests
├── syscall/      # Syscall behavior tests
├── shred/        # Shred parsing tests
└── serialize/    # Serialization tests
```

## Running Tests

From the build directory:

```bash
# Run all conformance tests
./bin/test_conformance ../fixtures all

# Run specific component tests
./bin/test_conformance ../fixtures txn

# Run with verbose output
./bin/test_conformance -v ../fixtures all

# Run built-in self-test (no fixtures needed)
./bin/test_conformance selftest
```

## Using solana-conformance Tool

For comprehensive testing, use the official solana-conformance tool:

```bash
# Clone the conformance repository
git clone https://github.com/firedancer-io/solana-conformance.git
cd solana-conformance

# Set up Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests against our library
python test.py --target path/to/libsol_compat.dylib
```

## Resources

- [Firedancer Conformance](https://github.com/firedancer-io/solana-conformance)
- [Test Vectors](https://github.com/firedancer-io/test-vectors)
- [Conformance Protobuf Schema](https://github.com/firedancer-io/test-vectors/tree/main/proto)
