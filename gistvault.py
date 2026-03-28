#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "cryptography>=42.0",
# ]
# ///
"""
Encrypted secret storage backed by GitHub Gists.

Usage:
    # Encrypt a file
    ./gistvault.py encrypt -p mypass -i secret.json -o secret.enc

    # Decrypt a file
    ./gistvault.py decrypt -p mypass -i secret.enc -o secret.json

    # Upload a file (encrypted) to a GitHub Gist
    ./gistvault.py upload -p mypass -i secret.json

    # Download from GitHub Gist and decrypt
    ./gistvault.py download -p mypass -o secret.json

If --password is omitted, you will be prompted (recommended, avoids shell history).
Upload/download require GISTVAULT_TOKEN env var (GitHub token with 'gist' scope).
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import shutil
import sys
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_LEN = 16
GIST_FILENAME = "gistvault.enc"
GIST_DESCRIPTION = "gistvault"
GITHUB_API = "https://api.github.com"
# Scrypt params: n=2**17, r=8, p=1  (~128MB memory, strong against GPU attacks)
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    raw = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


def _gist_token() -> str:
    token = os.environ.get("GISTVAULT_TOKEN")
    if not token:
        sys.exit("Set GISTVAULT_TOKEN env var to a GitHub token with 'gist' scope.")
    return token


def _github_request(method: str, url: str, token: str,
                    data: dict[str, Any] | None = None) -> Any:
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method, headers={
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"GitHub API error {e.code}: {e.read().decode()}")


def _find_gist(token: str, full: bool = False) -> dict[str, Any] | None:
    page = 1
    while True:
        gists: list[dict[str, Any]] = _github_request(
            "GET", f"{GITHUB_API}/gists?per_page=100&page={page}", token)
        if not gists:
            return None
        for g in gists:
            if GIST_FILENAME in g.get("files", {}):
                if full:
                    result: dict[str, Any] = _github_request("GET", g["url"], token)
                    return result
                return g
        page += 1


def _compact_path(p: Path) -> str:
    try:
        return "~/" + str(p.resolve().relative_to(Path.home()))
    except ValueError:
        return str(p.resolve())


def _expand_path(s: str) -> Path:
    return Path(os.path.expanduser(s))


def _read_source(src: Path) -> bytes:
    if not src.exists():
        sys.exit(f"Source file not found: {src}")
    return src.read_bytes()


def _encrypt_blob(password: str, plaintext: bytes,
                  input_path: Path, output_path: Path) -> str:
    envelope = json.dumps({
        "input": _compact_path(input_path),
        "output": _compact_path(output_path),
        "timestamp": datetime.now().isoformat(),
        "data": base64.b64encode(plaintext).decode("ascii"),
    }).encode("utf-8")
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    token = Fernet(key).encrypt(envelope)
    return base64.b64encode(salt + token).decode("ascii")


def _decrypt_blob(password: str, blob_text: str) -> dict[str, str]:
    try:
        raw = base64.b64decode(blob_text.strip(), validate=True)
    except (ValueError, UnicodeDecodeError):
        sys.exit("Encrypted data is not valid base64.")
    if len(raw) <= SALT_LEN:
        sys.exit("Encrypted data is corrupt or too short.")
    salt, token = raw[:SALT_LEN], raw[SALT_LEN:]
    key = derive_key(password, salt)
    try:
        decrypted = Fernet(key).decrypt(token)
    except InvalidToken:
        sys.exit("Decryption failed: wrong password or corrupted data.")
    envelope: dict[str, str] = json.loads(decrypted)
    return envelope


def _write_output(dst: Path, plaintext: bytes) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = dst.with_name(f"{dst.name}.bak.{ts}")
        shutil.copy2(dst, backup)
        print(f"Existing file backed up to {backup}")
    dst.write_bytes(plaintext)
    dst.chmod(0o600)


def upload(password: str, src: Path) -> None:
    plaintext = _read_source(src)
    blob = _encrypt_blob(password, plaintext, input_path=src, output_path=src)
    gh_token = _gist_token()
    existing = _find_gist(gh_token)
    payload: dict[str, Any] = {
        "description": GIST_DESCRIPTION,
        "files": {GIST_FILENAME: {"content": blob}},
    }
    if existing:
        _github_request("PATCH", existing["url"], gh_token, payload)
        print(f"Updated gist {existing['id']}")
    else:
        payload["public"] = False
        result = _github_request("POST", f"{GITHUB_API}/gists", gh_token, payload)
        print(f"Created gist {result['id']}")


def download(password: str, dst: Path | None) -> None:
    gh_token = _gist_token()
    gist = _find_gist(gh_token, full=True)
    if not gist:
        sys.exit(f"No gist found with file '{GIST_FILENAME}'.")
    envelope = _decrypt_blob(password, gist["files"][GIST_FILENAME]["content"])
    data = base64.b64decode(envelope["data"])
    if dst is None:
        saved_output = envelope.get("output", "")
        if not saved_output:
            sys.exit("No output path saved in gist and --output not provided.")
        confirm = input(f"Decrypt to {saved_output}? [y/N] ").strip().lower()
        if confirm != "y":
            sys.exit("Aborted.")
        dst = _expand_path(saved_output)
    _write_output(dst, data)
    print(f"Decrypted gist -> {dst}")


def encrypt(password: str, out_file: Path, src: Path) -> None:
    plaintext = _read_source(src)
    blob = _encrypt_blob(password, plaintext, input_path=src, output_path=src)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(blob + "\n")
    print(f"Encrypted {src} -> {out_file}")


def decrypt(password: str, in_file: Path, dst: Path | None) -> None:
    if not in_file.exists():
        sys.exit(f"Encrypted file not found: {in_file}")
    envelope = _decrypt_blob(password, in_file.read_text())
    data = base64.b64decode(envelope["data"])
    if dst is None:
        saved_output = envelope.get("output", "")
        if not saved_output:
            sys.exit("No output path saved in file and --output not provided.")
        confirm = input(f"Decrypt to {saved_output}? [y/N] ").strip().lower()
        if confirm != "y":
            sys.exit("Aborted.")
        dst = _expand_path(saved_output)
    _write_output(dst, data)
    print(f"Decrypted {in_file} -> {dst}")


def main() -> None:
    p = argparse.ArgumentParser(description="Encrypted secret storage backed by GitHub Gists.")
    p.add_argument("option", choices=["encrypt", "decrypt", "upload", "download"])
    p.add_argument("-p", "--password",
                   help="Password (omit to be prompted securely)")
    p.add_argument("-i", "--input", type=Path, default=None,
                   help="Input file path. "
                        "encrypt/upload: plaintext source. "
                        "decrypt: encrypted file.")
    p.add_argument("-o", "--output", type=Path, default=None,
                   help="Output file path. "
                        "encrypt: encrypted file. "
                        "decrypt/download: plaintext destination.")
    args = p.parse_args()

    password = args.password or getpass.getpass("Password: ")
    if not password:
        sys.exit("Password cannot be empty.")

    if args.option == "encrypt":
        if not args.input or not args.output:
            p.error("encrypt requires both --input and --output")
        encrypt(password, args.output, args.input)
    elif args.option == "decrypt":
        if not args.input:
            p.error("decrypt requires --input")
        decrypt(password, args.input, args.output)
    elif args.option == "upload":
        if not args.input:
            p.error("upload requires --input")
        upload(password, args.input)
    elif args.option == "download":
        download(password, args.output)


if __name__ == "__main__":
    main()