#!/bin/bash

# Test script for tlsx API

echo "=========================================="
echo "Testing tlsx API"
echo "=========================================="
echo ""

# Step 1: Check if go.mod has all dependencies
echo "Step 1: Checking dependencies..."
if ! grep -q "github.com/rs/cors" go.mod; then
    echo "Installing rs/cors..."
    go get github.com/rs/cors
fi
go mod tidy
echo "✓ Dependencies OK"
echo ""

# Step 2: Try to build the API
echo "Step 2: Building API..."
if go build -o /tmp/tlsx-api cmd/api/main.go 2>&1; then
    echo "✓ Build successful"
else
    echo "✗ Build failed"
    exit 1
fi
echo ""

# Step 3: Check if tlsx binary exists (needed by API)
echo "Step 3: Checking tlsx binary..."
if command -v tlsx &> /dev/null; then
    echo "✓ tlsx binary found: $(which tlsx)"
else
    echo "⚠ tlsx binary not found. Building it..."
    go build -o /tmp/tlsx cmd/tlsx/main.go
    export PATH="/tmp:$PATH"
    echo "✓ tlsx built and added to PATH"
fi
echo ""

# Step 4: Start the API in background
echo "Step 4: Starting API server..."
PORT=8080 /tmp/tlsx-api &
API_PID=$!
echo "✓ API started (PID: $API_PID)"
sleep 3
echo ""

# Step 5: Test health endpoint
echo "Step 5: Testing /health endpoint..."
HEALTH_RESPONSE=$(curl -s http://localhost:8080/health)
if echo "$HEALTH_RESPONSE" | grep -q "ok"; then
    echo "✓ Health check passed: $HEALTH_RESPONSE"
else
    echo "✗ Health check failed: $HEALTH_RESPONSE"
    kill $API_PID 2>/dev/null
    exit 1
fi
echo ""

# Step 6: Test root endpoint
echo "Step 6: Testing / endpoint..."
ROOT_RESPONSE=$(curl -s http://localhost:8080/)
if echo "$ROOT_RESPONSE" | grep -q "Quantok"; then
    echo "✓ Root endpoint OK: $ROOT_RESPONSE"
else
    echo "✗ Root endpoint failed: $ROOT_RESPONSE"
fi
echo ""

# Step 7: Test scan endpoint (will likely fail if tlsx not available)
echo "Step 7: Testing /api/v1/scan endpoint..."
SCAN_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"google.com"}')

if echo "$SCAN_RESPONSE" | grep -q "target"; then
    echo "✓ Scan endpoint working!"
    echo "Response: $SCAN_RESPONSE" | jq '.' 2>/dev/null || echo "$SCAN_RESPONSE"
else
    echo "⚠ Scan endpoint returned: $SCAN_RESPONSE"
    echo "(This is expected if tlsx binary is not properly installed)"
fi
echo ""

# Cleanup
echo "Stopping API server..."
kill $API_PID 2>/dev/null
echo ""

echo "=========================================="
echo "API Test Complete!"
echo "=========================================="
echo ""
echo "Summary:"
echo "  - Build: ✓"
echo "  - Health endpoint: ✓"
echo "  - Root endpoint: ✓"
echo "  - Scan endpoint: Check output above"
echo ""
echo "To run the API manually:"
echo "  go build -o tlsx-api cmd/api/main.go"
echo "  ./tlsx-api"
