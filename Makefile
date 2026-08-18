.PHONY: install dev test lint seed setup-context setup-redis build deploy-vm

PORT ?= 8082
ENV_FILE ?= .env

install:
	uv sync --all-extras

dev:
	uv run --env-file $(ENV_FILE) uvicorn threat_intel_agent.api:app --reload --port $(PORT)

test:
	uv run pytest -q

lint:
	uv run ruff check .

seed:
	uv run --env-file $(ENV_FILE) python -m scripts.seed_redis

setup-context:
	uv run --env-file $(ENV_FILE) python -m scripts.setup_context_retriever --env-file $(ENV_FILE)

setup-redis: seed setup-context

build:
	docker build -t redis-threat-intelligence-agent:local .

deploy-vm:
	./scripts/deploy_vm.sh
