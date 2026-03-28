# gistvault Architecture

## Overview

gistvault is a single-script CLI tool that encrypts files locally and syncs them via GitHub Gists. It uses password-based encryption so secrets can be stored on a public (unlisted) service safely.

## Components

```
gistvault.py (single file)
├── CLI layer          (main, argparse)
├── Crypto layer       (derive_key, _encrypt_blob, _decrypt_blob)
├── Path helpers       (_compact_path, _expand_path)
├── File I/O layer     (_read_source, _write_output)
├── GitHub Gist layer  (_gist_token, _github_request, _find_gist)
└── Commands           (encrypt, decrypt, upload, download)
```

### CLI Layer

`main()` parses arguments and dispatches to the appropriate command function. Password is prompted securely via `getpass` if not provided via `--password`.

### Crypto Layer

```
Password + Random Salt (16 bytes)
        │
        ▼
   Scrypt KDF (n=2^17, r=8, p=1)
        │
        ▼
   256-bit Key
        │
        ▼
   Fernet Encrypt/Decrypt (AES-128-CBC + HMAC-SHA256)
```

- **Key derivation**: Scrypt with ~128MB memory cost, resistant to GPU/ASIC brute-force
- **Encryption**: Fernet (symmetric, authenticated encryption)
- **Encrypted envelope**: the plaintext encrypted by Fernet is a JSON object containing metadata and file data:
  ```json
  {
    "input": "~/path/to/source",
    "output": "~/path/to/destination",
    "timestamp": "2026-03-28T05:35:00",
    "data": "<base64-encoded file content>"
  }
  ```
  Paths under `$HOME` are stored as `~/...` for portability.
- **Storage format**: `base64(salt || fernet_token)` — salt is prepended so decryption is self-contained

### File I/O Layer

- `_read_source`: reads plaintext file, exits if missing
- `_write_output`: writes decrypted output with:
  - Parent directory auto-creation
  - Timestamped backup of existing file (`.bak.YYYYMMDD_HHMMSS`)
  - Restrictive permissions (`0o600`)

### GitHub Gist Layer

- Uses `urllib` (stdlib) — no external HTTP dependencies
- Auth via `GISTVAULT_TOKEN` env var (GitHub PAT with `gist` scope)
- `_find_gist`: paginates through user's gists, matches by filename (`gistvault.enc`)
- Gists are created as **secret (unlisted)** — not searchable, but accessible via URL

## Data Flow

### encrypt (local)

```
plaintext file ──▶ _read_source ──▶ _encrypt_blob ──▶ base64 text file
```

### decrypt (local)

```
base64 text file ──▶ _decrypt_blob ──▶ envelope
                                         │
                         ┌───────────────┤
                         ▼               ▼
                   (if --output)   (if no --output)
                         │         read saved output path
                         │         prompt user for confirmation
                         │               │
                         └───────┬───────┘
                                 ▼
                          _write_output ──▶ plaintext file
```

### upload (to gist)

```
plaintext file ──▶ _read_source ──▶ _encrypt_blob ──▶ GitHub Gist API
                                                       (create or update)
```

### download (from gist)

```
GitHub Gist API ──▶ _decrypt_blob ──▶ envelope
(find by filename)                       │
                         ┌───────────────┤
                         ▼               ▼
                   (if --output)   (if no --output)
                         │         read saved output path
                         │         prompt user for confirmation
                         │               │
                         └───────┬───────┘
                                 ▼
                          _write_output ──▶ plaintext file
```

## Security Model

- **Encryption at rest**: all stored data (local files, gists) is encrypted
- **Password never stored**: derived key exists only in memory during execution
- **Gist visibility**: secret/unlisted — even if discovered, content is an opaque encrypted blob
- **Backup safety**: existing files are backed up before overwrite, never silently lost

## Dependencies

- **Runtime**: `cryptography` (Fernet + Scrypt) — declared in PEP 723 inline metadata
- **Dev**: `pytest`, `mypy`, `ruff` — declared in `pyproject.toml`
- **No external HTTP library**: uses Python stdlib `urllib`
