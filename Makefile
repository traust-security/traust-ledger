PYTHON ?= python3
RELEASE := ./release.py
BUMP_PARTS := patch minor major
MOCK_IDP_NAME ?= ledger-mock-idp
MOCK_IDP_PORT ?= 1080
DB_CONTAINER ?= traust-postgres
DB_IMAGE ?= docker.io/library/postgres:16
DB_PORT ?= 5432
DB_USER ?= traust
DB_PASSWORD ?= traust-test-only
DB_NAME ?= traust_test
LEDGER_TEST_DATABASE_URL ?= postgresql+psycopg://$(DB_USER):$(DB_PASSWORD)@127.0.0.1:$(DB_PORT)/$(DB_NAME)
export LEDGER_TEST_DATABASE_URL

.PHONY: help setup sync hooks lint lint-fix test test-integration coverage coverage-html coverage-all check-release status bump $(BUMP_PARTS) openapi container mock-idp mock-idp-stop db-up db-down

help:
	@echo "Targets ($(notdir $(CURDIR))):"
	@echo "  make setup          — uv sync + enable .githooks (run once per clone)"
	@echo "  make sync           — uv sync only"
	@echo "  make hooks          — git config core.hooksPath .githooks"
	@echo "  make lint           — ruff check + format --check"
	@echo "  make lint-fix       — ruff check --fix + format"
	@echo "  make test           — pytest unit tests"
	@echo "  make coverage       — pytest with terminal coverage report (unit only)"
	@echo "  make coverage-html  — coverage report + htmlcov/ (unit only)"
	@echo "  make coverage-all   — full coverage: starts mock-idp, runs all tests, generates htmlcov/"
	@echo "  make check-release  — VERSION + CHANGELOG gate for current branch vs main"
	@echo "  make status         — current version, tag, git state"
	@echo "  make bump patch|minor|major — bump VERSION + pyproject.toml"
	@echo "  make openapi        — regenerate docs/openapi.json (+ yaml if PyYAML available)"
	@echo "  make db-up          — start local database container for e2e tests"
	@echo "  make db-down        — stop and remove the database container"
	@echo "  make mock-idp       — start mock OIDC server (Docker) for dev/integration tests"
	@echo "  make mock-idp-stop  — stop mock OIDC server"

setup: sync hooks
	@echo "ready — local hooks enabled (.githooks). Bypass: git commit --no-verify"

sync:
	uv sync --extra service --extra cli

hooks:
	git config core.hooksPath .githooks
	@chmod +x .githooks/* 2>/dev/null || true

lint:
	uv run ruff check .
	uv run ruff format --check .

lint-fix:
	uv run ruff check --fix .
	uv run ruff format .

test:
	uv run pytest tests/ -q -m "not integration"

test-integration:
	uv run pytest tests/ -q -m integration

coverage:
	uv run pytest tests/ --cov=traust_ledger --cov-report=term-missing -q -m "not integration"

coverage-html:
	uv run pytest tests/ --cov=traust_ledger --cov-report=term-missing --cov-report=html -q -m "not integration"

coverage-all: mock-idp
	@echo "Running full coverage (unit + integration)..."
	uv run pytest tests/ --cov=traust_ledger --cov-report=term-missing --cov-report=html -q
	@$(MAKE) mock-idp-stop
	@echo "Full report: open htmlcov/index.html"

check-release:
	@base="$${RELEASE_BASE:-origin/main}"; \
	head="$${RELEASE_HEAD:-HEAD}"; \
	$(PYTHON) ci/gates.py mr "$$base" "$$head"

$(BUMP_PARTS):
	@:

status:
	$(PYTHON) $(RELEASE) status

bump:
	@part="$(filter $(BUMP_PARTS),$(MAKECMDGOALS))"; \
	if [ -z "$$part" ]; then \
		echo "usage: make bump patch|minor|major" >&2; \
		exit 1; \
	fi; \
	$(PYTHON) $(RELEASE) bump $$part

openapi:
	@mkdir -p docs
	@tmpdir=$$(mktemp -d); \
	LAAS_DATA_DIR=$$tmpdir uv run python -c "from traust_ledger.service.app import create_app; import json, sys; json.dump(create_app(validate_config=False).openapi(), sys.stdout, indent=2)" > docs/openapi.json; \
	LAAS_DATA_DIR=$$tmpdir uv run python -c "import importlib.util, sys; from traust_ledger.service.app import create_app; spec=create_app(validate_config=False).openapi(); (sys.exit(0) if importlib.util.find_spec('yaml') is None else None); import yaml; open('docs/openapi.yaml','w').write(yaml.dump(spec, default_flow_style=False, sort_keys=False)); print('Wrote docs/openapi.yaml')"; \
	rm -rf $$tmpdir
	@echo "Wrote docs/openapi.json"

container:
	podman build -f Containerfile -t laas:dev .

mock-idp:
	@docker rm -f $(MOCK_IDP_NAME) 2>/dev/null || true
	docker run --rm -d -p $(MOCK_IDP_PORT):1080 --name $(MOCK_IDP_NAME) mockserver/mockserver
	@echo "Mock IdP running at http://localhost:$(MOCK_IDP_PORT)"
	@echo "Use for integration tests: make test-integration"

mock-idp-stop:
	docker stop $(MOCK_IDP_NAME) 2>/dev/null || true

db-up:
	@if podman container exists $(DB_CONTAINER) 2>/dev/null; then \
		echo "$(DB_CONTAINER) already running"; \
	else \
		podman run --name $(DB_CONTAINER) --rm -d \
			-e POSTGRES_USER=$(DB_USER) \
			-e POSTGRES_PASSWORD=$(DB_PASSWORD) \
			-e POSTGRES_DB=$(DB_NAME) \
			-p 127.0.0.1:$(DB_PORT):5432 \
			-v traust-postgres-data:/var/lib/postgresql/data \
			$(DB_IMAGE); \
		echo "waiting for database..."; \
		for i in $$(seq 1 30); do \
			podman exec $(DB_CONTAINER) pg_isready -U $(DB_USER) -q 2>/dev/null && break; \
			sleep 1; \
		done; \
		echo "$(DB_CONTAINER) ready on port $(DB_PORT)"; \
	fi
	@echo "LEDGER_TEST_DATABASE_URL=$(LEDGER_TEST_DATABASE_URL)"

db-down:
	@podman stop $(DB_CONTAINER) 2>/dev/null || true
