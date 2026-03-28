.PHONY: lint typecheck test check

lint:
	uv run ruff check gistvault.py tests/

typecheck:
	uv run mypy gistvault.py tests/

test:
	uv run pytest tests/ -v

check: lint typecheck test
