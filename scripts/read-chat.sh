#!/usr/bin/env bash
# Read Hum's Telegram conversation from session transcripts.
# Usage: bash scripts/read-chat.sh [--last N]
#   --last N   Show last N messages (default: 20)
set -uo pipefail

RUNTIME="podman"
command -v podman &>/dev/null || RUNTIME="docker"
CONTAINER="openclaw-vault"
LAST="${2:-20}"

if [ "${1:-}" = "--last" ] && [ -n "${2:-}" ]; then
    LAST="$2"
fi

$RUNTIME exec "$CONTAINER" sh -c "cat /home/vault/.openclaw/agents/main/sessions/*.jsonl 2>/dev/null" | python3 -c "
import sys, json

messages = []
for line in sys.stdin:
    try:
        entry = json.loads(line.strip())
        etype = entry.get('type', '')
        if etype == 'message':
            msg = entry.get('message', {})
            role = msg.get('role', '')
            content = msg.get('content', '')
            ts = entry.get('timestamp', '')[:19]

            texts = []
            if isinstance(content, str) and content.strip():
                texts.append(content.strip())
            elif isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get('type') == 'text':
                        texts.append(block['text'].strip())

            for text in texts:
                # Skip system/heartbeat messages
                if 'HEARTBEAT' in text[:50] or text.startswith('Read HEARTBEAT'):
                    continue
                # Clean up untrusted metadata prefix
                if 'untrusted metadata' in text[:100]:
                    parts = text.split('\n\n', 1)
                    text = parts[-1] if len(parts) > 1 else text

                prefix = '\033[94mUSER\033[0m' if role == 'user' else '\033[93mHUM\033[0m' if role == 'assistant' else role.upper()
                messages.append((ts, prefix, text[:500]))

        elif etype == 'tool_result' or (etype == 'message' and entry.get('message', {}).get('role') == 'tool'):
            pass  # Skip raw tool results in chat view

    except:
        pass

# Show last N messages
for ts, prefix, text in messages[-int(sys.argv[1]):]:
    print(f'[{ts}] {prefix}: {text[:300]}')
    print()
" "$LAST" 2>&1
