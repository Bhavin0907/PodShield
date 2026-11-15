# PodShield test targets. Run from the repository root (podshield/).
#
#   make test-unit          fast, no Podman needed (runs anywhere)
#   make test-api           API tests with FastAPI's TestClient
#   make test-integration   needs real Podman; tests skip (with a reason) when a tool is missing
#   make test-frontend      Vitest + React Testing Library
#   make test-e2e           Playwright: starts a demo server, or targets BASE_URL (e.g. the RHEL VM)
#   make test-all           everything above
#   make coverage           unit + API tests with a coverage report (fails under 85 %)
#
# On the RHEL VM run the root-only integration tests with sudo, keeping the venv:
#   sudo env "PATH=$$PATH" make test-integration

BACKEND  := backend
FRONTEND := frontend
PYTHON   ?= $(shell test -x $(BACKEND)/.venv/bin/python && echo $(BACKEND)/.venv/bin/python || echo python3)
# Absolute when it is a path (we cd into backend/), a bare command name otherwise.
PYABS    := $(if $(findstring /,$(PYTHON)),$(abspath $(PYTHON)),$(PYTHON))
PYTEST   := cd $(BACKEND) && $(PYABS) -m pytest
# Empty: test-e2e starts the self-contained demo server (fake Podman, real API/DB/UI).
# Set it to test a real install, e.g. from your laptop:  make test-e2e BASE_URL=http://rhel-vm:8000
BASE_URL ?=

.PHONY: test-unit test-api test-integration test-frontend test-e2e test-all coverage coverage-frontend typecheck security perf

test-unit:
	$(PYTEST) -m "unit and not integration" --ignore=tests/integration

test-api:
	$(PYTEST) tests/test_api.py tests/test_t3_api.py tests/test_main.py

test-integration:
	$(PYTEST) tests/integration -m integration -rs

test-frontend:
	cd $(FRONTEND) && npm test --silent

test-e2e:
	cd $(FRONTEND) && BASE_URL=$(BASE_URL) npx playwright test

test-all: test-unit test-api test-integration test-frontend test-e2e

coverage-frontend:
	cd $(FRONTEND) && npm run test:coverage --silent

coverage:
	$(PYTEST) --ignore=tests/integration --cov=podshield --cov-report=term-missing:skip-covered \
		--cov-report=html:../docs/coverage --cov-fail-under=85

typecheck:
	cd $(BACKEND) && $(PYABS) -m mypy podshield

security:
	cd $(BACKEND) && $(PYABS) -m bandit -q -r podshield -c pyproject.toml
	cd $(FRONTEND) && npm audit --audit-level=high

# 20-image scan benchmark. Synthetic by default; on the RHEL VM use the real images:
#   make perf PERF_ARGS="--real --limit 20 --concurrency 4"
PERF_ARGS ?= --images 20 --concurrency 4
perf:
	cd $(BACKEND) && PYTHONPATH=. $(PYABS) -m tests.perf.perf_scan $(PERF_ARGS)
