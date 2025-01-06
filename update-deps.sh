#!/usr/bin/env bash

set -eu

# Update all dependencies to their latest versions
go get -u ./...

# Clean up go.mod and go.sum files
go mod tidy

echo "Dependencies updated and go.mod tidied up."
