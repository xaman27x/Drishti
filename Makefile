.PHONY: install run test lint format verify-ocsf build-ocsf check

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
	python scripts/verify_ocsf_vendor.py
	python scripts/verify_ocsf_bundle.py
	python scripts/build_ocsf_bundle.py --check

build-ocsf:
	python scripts/build_ocsf_bundle.py

check: lint verify-ocsf test
