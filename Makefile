PYTHON ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: install demo lint typecheck test security check

$(BIN)/iam-audit: pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install -e ".[dev]"
	touch $(BIN)/iam-audit

install: $(BIN)/iam-audit

demo: install
	$(BIN)/iam-audit demo

lint: install
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

typecheck: install
	$(BIN)/mypy

test: install
	$(BIN)/pytest

security: install
	$(BIN)/bandit -r src -q

check: lint typecheck security test
