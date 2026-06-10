ifdef DOCKER
  RUN_PREFIX := docker compose run --rm proxy
else
  RUN_PREFIX :=
endif
COV_REPORT ?= term-missing

.SILENT: help
all: help

lint: ## Check for linting errors
	$(RUN_PREFIX) ruff check

lint-fix: ## Fix linting errors
	$(RUN_PREFIX) ruff check --fix --show-fixes

format: ## Format code
	$(RUN_PREFIX) ruff format

format-diff: ## Show formatting differences
	$(RUN_PREFIX) ruff format --diff

type-check: ## Check for typing errors
	$(RUN_PREFIX) mypy

clear-type-check-cache: ## Remove mypy cache
	rm -rf ~/.cache/mypy

spelling-check: ## Check spelling mistakes
	$(RUN_PREFIX) codespell . -I.codespellignore

spelling-fix: ## Fix spelling mistakes
	$(RUN_PREFIX) codespell . .codespellignore --write-changes --interactive=3

module-dependencies-check: ## Check cross-dependencies between modules
	$(RUN_PREFIX) tach check -exact

test: ## Runs automated tests with code coverage
	$(RUN_PREFIX) pytest --cov --cov-fail-under=100 --cov-branch --cov-report=$(COV_REPORT)

test-cov-xml: ## Runs automated tests with code coverage and exports a code coverage report to an XML file
	$(RUN_PREFIX) pytest --cov --cov-fail-under=100 --cov-branch --cov-report=xml

check: lint format-diff type-check spelling-check module-dependencies-check test ## Runs all checks
fix: lint-fix format spelling-fix ## Runs all fixers

help: ## Display available commands
	echo "Available make commands:"
	echo
	grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m  %-30s\033[0m %s\n", $$1, $$2}'
