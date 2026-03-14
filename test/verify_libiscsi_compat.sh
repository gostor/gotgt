#!/bin/bash
# Verify libiscsi compatibility - validates iSCSI protocol format

set -e

echo "=== iSCSI Protocol Format Verification ==="
echo

cd "$(dirname "$0")/.."

# Run all protocol tests
echo "1. Running protocol format tests..."
go test ./pkg/port/iscsit/... -v -run "Test.*Format" 2>&1 | grep -E "(PASS|FAIL|===)"

echo
echo "2. Running TSIH bitmap tests..."
go test ./pkg/port/iscsit/... -v -run "TestTSIH" 2>&1 | grep -E "(PASS|FAIL|===)"

echo
echo "3. Running object pool tests..."
go test ./pkg/port/iscsit/... -v -run "Test.*Pool" 2>&1 | grep -E "(PASS|FAIL|===)"

echo
echo "4. Running all unit tests..."
go test ./pkg/... ./mock/... 2>&1 | grep -E "(ok|FAIL)"

echo
echo "5. Benchmark tests..."
go test ./pkg/port/iscsit/... -bench=. -benchtime=100ms 2>&1 | grep -E "(Benchmark|PASS|ns/op)"

echo
echo "=== Verification Complete ==="
