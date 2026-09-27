PYTHON ?= python

.PHONY: install run test lint format verify-ocsf build-ocsf check release-check

install:
	python -m pip install -e ".[dev]"

run:
	uvicorn drishti.api.app:create_app --factory --host 0.0.0.0 --port 8080 --reload

test:
	pytest

lint:
	ruff check .
	mypy src

format:
	ruff format .
	ruff check --fix .

verify-ocsf:
	$(PYTHON) scripts/verify_ocsf_vendor.py
	$(PYTHON) scripts/verify_ocsf_bundle.py
	$(PYTHON) scripts/build_ocsf_bundle.py --check

build-ocsf:
	$(PYTHON) scripts/build_ocsf_bundle.py

check: lint verify-ocsf test

release-check: check