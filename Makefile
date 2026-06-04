.PHONY: help install dev test lint typecheck format db-upgrade db-revision \
        run-api run-worker docker-build docker-up docker-down clean

PYTHON ?= python3

help:
	@echo "PEGASE makefile targets:"
	@echo "  install        install runtime deps"
	@echo "  dev            install runtime + dev deps"
	@echo "  test           run pytest"
	@echo "  lint           run ruff"
	@echo "  typecheck      run mypy"
	@echo "  format         run ruff format"
	@echo "  db-upgrade     apply Alembic migrations"
	@echo "  db-revision m='msg'  create new Alembic revision"
	@echo "  run-api        run FastAPI dev server"
	@echo "  run-worker     run Celery worker"
	@echo "  docker-build   build the Docker image"
	@echo "  docker-up      docker compose up"
	@echo "  docker-down    docker compose down"

install:
	$(PYTHON) -m pip install -e .

dev:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check pegase tests

typecheck:
	$(PYTHON) -m mypy pegase

format:
	$(PYTHON) -m ruff format pegase tests

db-upgrade:
	$(PYTHON) -m alembic upgrade head

db-revision:
	$(PYTHON) -m alembic revision --autogenerate -m "$(m)"

run-api:
	$(PYTHON) -m uvicorn pegase.api.main:app --reload --host 0.0.0.0 --port 8000

run-worker:
	$(PYTHON) -m celery -A pegase.tasks.celery_app worker --loglevel=INFO

docker-build:
	docker build -t pegase:latest .

docker-up:
	docker compose up -d --build

docker-down:
	docker compose down

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info
