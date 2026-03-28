# gistvault

Encrypted secret storage backed by GitHub Gists.

## Project structure

- Single-script tool: `gistvault.py` (PEP 723 inline metadata, runnable via `uv run`)
- This is a uv project — dev dependencies in `pyproject.toml`, runtime deps in script metadata (keep in sync)
- Python >= 3.13
- Tests in `tests/` — split by layer: `test_crypto.py`, `test_fileio.py`, `test_gist.py`, `test_commands.py`
- Shared test fixtures in `tests/conftest.py`
- Architecture docs in `doc/architecture.md`

## Development workflow

Every major change must follow this flow:

1. Write/modify code in `gistvault.py` (keep it as a single script)
2. Write/update unit tests (every major function needs a test)
3. Run `make check` (ruff + mypy strict + pytest) — all must pass
4. Update `doc/architecture.md` if the change affects architecture, data flow, or adds commands
5. Commit with a descriptive message (no Co-Authored-By)
6. When unclear about user intent, ask questions instead of guessing

## Commands

- Run: `uv run gistvault.py <command>`
- Lint: `uv run ruff check gistvault.py tests/`
- Type check: `uv run mypy gistvault.py tests/`
- Test: `uv run pytest tests/ -v`
- All checks: `make check`

Individual Makefile targets: `make lint`, `make typecheck`, `make test`

## Script commands

```
encrypt   Encrypt a local file             (-i, -o required)
decrypt   Decrypt a local encrypted file   (-i required; -o optional, uses saved path)
upload    Encrypt and push to GitHub Gist   (-i required)
download  Pull from GitHub Gist and decrypt (-n required; -o optional, uses saved path)
list      List all encrypted gist entries
delete    Delete an encrypted gist entry    (-n required)
rename    Rename a gist entry               (-n, --new-name required)
```

## Environment

- `GISTVAULT_TOKEN` — GitHub personal access token with `gist` scope (required for upload/download/list/delete/rename)

## Key design decisions

- **Single script**: everything lives in `gistvault.py`. No splitting into modules.
- **Multi-gist**: each uploaded file gets its own secret (unlisted) gist, named `<filename>.enc`
- **Encrypted envelope**: the encrypted blob contains a JSON envelope with `input`, `output`, `timestamp`, and `data` (base64-encoded file content). All metadata is encrypted.
- **Path compaction**: paths under `$HOME` are stored as `~/...` for portability across machines
- **Password confirmation**: encrypt/upload prompt twice when password is entered interactively. Skipped when using `-p` flag (for scripting).
- **Gist discovery**: gists are found by matching `description == "gistvault"` and the filename. No IDs to memorize.
- **Backup on overwrite**: `_write_output` creates a timestamped `.bak` before overwriting existing files
- **CLI framework**: typer with subcommands — each command declares its own required/optional options via `Annotated` type hints
- **No external HTTP library**: uses Python stdlib `urllib` for GitHub API calls
- **Crypto**: Scrypt KDF (n=2^17, r=8, p=1) + Fernet (AES-128-CBC + HMAC-SHA256)

## Testing conventions

- Use `pytest` as the test framework — no `unittest.mock`, use `monkeypatch` instead
- Tests are plain functions (no classes), grouped by file/layer
- Mock GitHub API calls via `monkeypatch.setattr` on `gistvault._github_request`, `gistvault._find_gist`, etc.
- Use `tmp_path` fixture for file I/O tests
- Use `capsys` for testing printed output
- The `sample_file` fixture (in conftest.py) creates a temp JSON file for reuse
