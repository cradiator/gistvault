# gistvault

Encrypted secret storage backed by GitHub Gists.

## Project structure

- Single-script tool: `gistvault.py` (PEP 723 inline metadata, runnable via `uv run`)
- This is a uv project — dev dependencies in `pyproject.toml`, runtime deps in script metadata (keep in sync)
- Python >= 3.13

## Development rules

- Every major step must be committed with git
- The script must pass `ruff`, `mypy`, and `pytest` before each commit
- Every major function must have a unit test
- Keep it as a single runnable script file

## Commands

- Run: `uv run gistvault.py <command>`
- Lint: `uv run ruff check gistvault.py`
- Type check: `uv run mypy gistvault.py`
- Test: `uv run pytest tests/`

## Environment

- `ADC_GIST_TOKEN` — GitHub personal access token with `gist` scope (required for upload/download/list/delete)
