#!/usr/bin/env bash
# Test: API keys not visible inside the OpenClaw container (Path A only)
set -euo pipefail

RUNTIME="${RUNTIME:-podman}"
CONTAINER="openclaw-vault"

echo "=== API Key Isolation Tests ==="

# Test 1: No API key env vars
echo -n "  No API key in env: "
key_found=$($RUNTIME exec "$CONTAINER" sh -c 'env | grep -iE "api_key|api-key|apikey|bearer" | grep -v HTTP_PROXY || true')
if [ -z "$key_found" ]; then
    echo "PASS"
else
    echo "FAIL — found key in environment: $key_found"
    exit 1
fi

# Test 2: No API key in process list
echo -n "  No API key in /proc: "
proc_key=$($RUNTIME exec "$CONTAINER" sh -c 'cat /proc/*/environ 2>/dev/null | tr "\0" "\n" | grep -iE "api_key|apikey" | grep -v HTTP_PROXY || true')
if [ -z "$proc_key" ]; then
    echo "PASS"
else
    echo "FAIL — found key in /proc"
    exit 1
fi

echo "=== All API key isolation tests passed ==="
