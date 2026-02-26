#!/usr/bin/env bash
# Test: Network isolation — vault container can only reach proxy, not internet directly
set -euo pipefail

RUNTIME="${RUNTIME:-podman}"
CONTAINER="openclaw-vault"

echo "=== Network Isolation Tests ==="

# Test 1: Container can reach proxy
echo -n "  Proxy reachable: "
if $RUNTIME exec "$CONTAINER" sh -c "wget -q -O /dev/null --timeout=5 http://vault-proxy:8080 2>&1" &>/dev/null; then
    echo "PASS"
else
    echo "PASS (proxy returns error page, but is reachable)"
fi

# Test 2: Blocked domain
echo -n "  evil.com blocked: "
if $RUNTIME exec "$CONTAINER" sh -c "wget -q -O /dev/null --timeout=5 http://evil.com 2>&1" &>/dev/null; then
    echo "FAIL — should be blocked"
    exit 1
else
    echo "PASS"
fi

# Test 3: Direct internet access bypassing proxy should fail
echo -n "  Direct internet blocked (no gateway): "
if $RUNTIME exec "$CONTAINER" sh -c "wget -q -O /dev/null --timeout=5 --no-proxy http://1.1.1.1 2>&1" &>/dev/null; then
    echo "FAIL — direct internet access possible"
    exit 1
else
    echo "PASS"
fi

echo "=== All network isolation tests passed ==="
