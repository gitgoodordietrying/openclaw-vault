# openclaw-VAULT: Hardened OpenClaw Container
# Defense-in-depth Layer 2 — rootless container with minimal attack surface
#
# Build:  podman build -t openclaw-vault -f Containerfile .
# Or:     docker build -t openclaw-vault -f Containerfile .

FROM node:20-alpine AS builder

# Install OpenClaw CLI
RUN npm install -g @anthropic-ai/openclaw@latest

# --- Production stage ---
FROM node:20-alpine

LABEL maintainer="openclaw-VAULT" \
      description="Hardened OpenClaw sandbox — rootless, read-only, proxy-gated"

# Remove package managers and network tools after base setup
# Keep only what OpenClaw needs to function
RUN apk --no-cache add tini ca-certificates \
    && rm -rf /sbin/apk /usr/bin/wget /usr/bin/curl \
    && rm -rf /var/cache/apk/* /tmp/*

# Copy OpenClaw from builder
COPY --from=builder /usr/local/lib/node_modules /usr/local/lib/node_modules
COPY --from=builder /usr/local/bin/openclaw /usr/local/bin/openclaw

# Create non-root user
RUN addgroup -g 1000 -S vault \
    && adduser -u 1000 -S vault -G vault -h /home/vault -s /bin/sh

# Hardened OpenClaw config
COPY config/openclaw-hardening.yml /home/vault/.config/openclaw/config.yml
RUN chown -R vault:vault /home/vault

# Proxy configuration — all traffic routes through vault-proxy sidecar
# The container NEVER contacts external services directly
ENV HTTP_PROXY=http://vault-proxy:8080 \
    HTTPS_PROXY=http://vault-proxy:8080 \
    NO_PROXY=localhost,127.0.0.1 \
    NODE_TLS_REJECT_UNAUTHORIZED=0 \
    HOME=/home/vault

# Run as non-root
USER vault
WORKDIR /home/vault/workspace

# tini handles PID 1 responsibilities (signal forwarding, zombie reaping)
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["openclaw", "--config", "/home/vault/.config/openclaw/config.yml"]
