.PHONY: lint typecheck test check

lint:
	uv run ruff check src/gistvault/ tests/

typecheck:
	uv run mypy src/gistvault/ tests/

test:
	uv run pytest tests/ -v

check: lint typecheck test
