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
