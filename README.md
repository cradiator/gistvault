# gistvault

Encrypted secret storage backed by GitHub Gists.

A CLI tool (`gv`) that encrypts files locally and syncs them via secret (unlisted) GitHub Gists. No gist IDs to memorize -- files are discovered automatically by name.

## Quick start

Install with [uv](https://docs.astral.sh/uv/):

```bash
uv tool install git+https://github.com/cradiator/gistvault
```

This gives you the `gv` command globally.

## Requirements

- Python >= 3.13
- [uv](https://docs.astral.sh/uv/)

## Setup

1. Create a GitHub personal access token with **only the `gist` scope** (no other permissions needed):
   **GitHub > Settings > Developer settings > Personal access tokens > Tokens (classic)**

2. Add it to your shell profile:
   ```bash
   export GISTVAULT_TOKEN="ghp_your_token_here"
   ```

## Usage

```bash
# Encrypt a file locally
gv encrypt -i secret.json -o secret.enc

# Decrypt a local file
gv decrypt -i secret.enc -o secret.json

# Decrypt using the saved output path (prompts for confirmation)
gv decrypt -i secret.enc

# Upload a file (encrypted) to a GitHub Gist
gv upload -i secret.json

# Upload with a custom gist name
gv upload -i secret.json --new-name credentials.json

# List all stored files
gv list

# Download by name
gv download -n secret.json

# Download to a specific path
gv download -n secret.json -o ~/restored.json

# Rename a gist entry
gv rename -n old.json --new-name new.json

# Delete a stored file
gv delete -n secret.json
```

If `--password` / `-p` is omitted, you will be prompted securely (recommended).

## How it works

```
plaintext file --> Scrypt KDF (password + salt) --> Fernet encrypt --> base64 --> GitHub Gist
```

- **Encryption**: Scrypt (n=2^17, r=8, p=1) for key derivation + Fernet (AES-128-CBC + HMAC-SHA256)
- **Envelope**: encrypted blob contains a JSON envelope with the file data, original input/output paths, and a timestamp -- all encrypted together
- **Storage**: each file is stored as a separate secret (unlisted) gist named `<filename>.enc`
- **Discovery**: gists are found by matching description (`gistvault`) + filename -- no IDs to track
- **Safety**: existing files are backed up with a timestamp before overwriting

## Security

- All stored data (local `.enc` files and gists) is fully encrypted
- Password is never stored -- the derived key exists only in memory during execution
- Encrypt/upload prompt for password confirmation when entered interactively
- Gists are secret (unlisted) -- not searchable or listed on your profile, but accessible via direct URL
- Even if a gist URL is discovered, the content is an opaque encrypted blob

## Development

```bash
make check    # run all checks (ruff + mypy + pytest)
make lint     # ruff only
make typecheck # mypy only
make test     # pytest only
```

See [CLAUDE.md](CLAUDE.md) for development workflow and conventions.
