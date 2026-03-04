.PHONY: help setup start stop kill nuclear verify

SHELL := /bin/bash

# Runtime detection: prefer podman, fall back to docker
RUNTIME := $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)
COMPOSE := $(RUNTIME) compose

help: ## Show available commands
	@echo ""
	@echo "  openclaw-vault"
	@echo "  =============="
	@echo ""
	@echo "  runtime: $(RUNTIME)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
	@echo ""

setup: ## Build and configure the hardened container environment
	@bash scripts/setup.sh

start: ## Start the vault container and proxy sidecar
	@$(COMPOSE) up -d

stop: ## Gracefully stop the vault container
	@$(COMPOSE) stop

kill: ## Force stop the vault container immediately
	@bash scripts/kill.sh --hard

nuclear: ## Remove all containers, images, and volumes — full reset
	@bash scripts/kill.sh --nuclear

verify: ## Run 15-point security verification checks
	@bash scripts/verify.sh
