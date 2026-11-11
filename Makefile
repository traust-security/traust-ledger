.PHONY: help setup sync hooks lint lint-fix test coverage coverage-html

help:
	@echo "Targets ($(notdir $(CURDIR))):"
	@echo "  make setup          — uv sync + enable .githooks (run once per clone)"
	@echo "  make sync           — uv sync only"
	@echo "  make hooks          — git config core.hooksPath .githooks"
	@echo "  make lint           — ruff check + format --check"
	@echo "  make lint-fix       — ruff check --fix + format"
	@echo "  make test           — pytest, parallel via pytest-xdist (cosign on PATH runs the signing tests)"
	@echo "  make coverage       — pytest with terminal coverage report"
	@echo "  make coverage-html  — coverage report + htmlcov/"

setup: sync hooks

sync:
	uv sync

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
	uv run pytest tests/ -q -n auto

coverage:
	uv run pytest tests/ --cov=traust_ledger --cov-report=term-missing -q

coverage-html:
	uv run pytest tests/ --cov=traust_ledger --cov-report=term-missing --cov-report=html -q
