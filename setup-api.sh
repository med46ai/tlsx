#!/bin/bash

# Setup script for tlsx API server

echo "Installing rs/cors dependency..."
go get github.com/rs/cors

echo "Tidying go.mod..."
go mod tidy

echo "Building API server..."
go build -o tlsx-api cmd/api/main.go

echo ""
echo "Build complete! Run the server with:"
echo "  ./tlsx-api"
echo ""
echo "Or with custom port:"
echo "  PORT=3000 ./tlsx-api"
