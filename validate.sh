#!/bin/sh

echo "Requesting cert for $1"

echo "$2" | ndnsec cert-dump -f - -p | grep -A 1 "Certificate Name"

echo "..."
echo "..."
echo "Allow anything for testing"
echo "..."
echo "..."
exit 0
