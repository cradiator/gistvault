#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "cryptography>=42.0",
# ]
# ///
"""
Encrypt/decrypt the gcloud ADC file with a password.

Usage:
    # Encrypt ADC -> local encrypted file
    ./adc.py encrypt -p mypass -o adc.enc

    # Decrypt local encrypted file -> ADC
    ./adc.py decrypt -p mypass -i adc.enc

    # Upload ADC (encrypted) to a GitHub Gist
    ./adc.py upload -p mypass

    # Upload a specific file instead of the default ADC path
    ./adc.py upload -p mypass -i /path/to/credentials.json

    # Download from GitHub Gist and decrypt -> ADC
    ./adc.py download -p mypass

    # Download and decrypt to a specific path
    ./adc.py download -p mypass -o /path/to/credentials.json

If --password is omitted, you will be prompted (recommended, avoids shell history).
Upload/download require ADC_GIST_TOKEN env var (GitHub token with 'gist' scope).
"""

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

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ADC_PATH = Path.home() / ".config" / "gcloud" / "application_default_credentials.json"
SALT_LEN = 16
GIST_FILENAME = "adc.enc"
GIST_DESCRIPTION = "adc-crypt"
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
    token = os.environ.get("ADC_GIST_TOKEN")
    if not token:
        sys.exit("Set ADC_GIST_TOKEN env var to a GitHub token with 'gist' scope.")
    return token


def _github_request(method: str, url: str, token: str,
                    data: dict | None = None) -> dict:
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


def _find_gist(token: str, full: bool = False) -> dict | None:
    page = 1
    while True:
        gists = _github_request(
            "GET", f"{GITHUB_API}/gists?per_page=100&page={page}", token)
        if not gists:
            return None
        for g in gists:
            if GIST_FILENAME in g.get("files", {}):
                if full:
                    return _github_request("GET", g["url"], token)
                return g
        page += 1


def _read_source(src: Path) -> bytes:
    if not src.exists():
        sys.exit(f"Source file not found: {src}\n"
                 f"Run 'gcloud auth application-default login' first.")
    return src.read_bytes()


def _encrypt_blob(password: str, plaintext: bytes) -> str:
    salt = os.urandom(SALT_LEN)
    key = derive_key(password, salt)
    token = Fernet(key).encrypt(plaintext)
    return base64.b64encode(salt + token).decode("ascii")


def _decrypt_blob(password: str, blob_text: str) -> bytes:
    try:
        raw = base64.b64decode(blob_text.strip(), validate=True)
    except (ValueError, UnicodeDecodeError):
        sys.exit("Encrypted data is not valid base64.")
    if len(raw) <= SALT_LEN:
        sys.exit("Encrypted data is corrupt or too short.")
    salt, token = raw[:SALT_LEN], raw[SALT_LEN:]
    key = derive_key(password, salt)
    try:
        return Fernet(key).decrypt(token)
    except InvalidToken:
        sys.exit("Decryption failed: wrong password or corrupted data.")


def _write_adc(dst: Path, plaintext: bytes) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = dst.with_name(f"{dst.name}.bak.{ts}")
        shutil.copy2(dst, backup)
        print(f"Existing file backed up to {backup}")
    dst.write_bytes(plaintext)
    dst.chmod(0o600)


def upload(password: str, src: Path) -> None:
    blob = _encrypt_blob(password, _read_source(src))
    gh_token = _gist_token()
    existing = _find_gist(gh_token)
    payload = {
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


def download(password: str, dst: Path) -> None:
    gh_token = _gist_token()
    gist = _find_gist(gh_token, full=True)
    if not gist:
        sys.exit(f"No gist found with file '{GIST_FILENAME}'.")
    plaintext = _decrypt_blob(password, gist["files"][GIST_FILENAME]["content"])
    _write_adc(dst, plaintext)
    print(f"Decrypted gist -> {dst}")


def encrypt(password: str, out_file: Path, src: Path) -> None:
    blob = _encrypt_blob(password, _read_source(src))
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(blob + "\n")
    print(f"Encrypted {src} -> {out_file}")


def decrypt(password: str, in_file: Path, dst: Path) -> None:
    if not in_file.exists():
        sys.exit(f"Encrypted file not found: {in_file}")
    plaintext = _decrypt_blob(password, in_file.read_text())
    _write_adc(dst, plaintext)
    print(f"Decrypted {in_file} -> {dst}")


def main() -> None:
    p = argparse.ArgumentParser(description="Encrypt/decrypt gcloud ADC file.")
    p.add_argument("option", choices=["encrypt", "decrypt", "upload", "download"])
    p.add_argument("-p", "--password",
                   help="Password (omit to be prompted securely)")
    p.add_argument("-i", "--input", type=Path, default=None,
                   help="Input file path. "
                        "encrypt/upload: plaintext source (default: ADC path). "
                        "decrypt: encrypted file (default: ./adc.enc).")
    p.add_argument("-o", "--output", type=Path, default=None,
                   help="Output file path. "
                        "encrypt: encrypted file (default: ./adc.enc). "
                        "decrypt/download: plaintext destination (default: ADC path).")
    args = p.parse_args()

    password = args.password or getpass.getpass("Password: ")
    if not password:
        sys.exit("Password cannot be empty.")

    if args.option == "encrypt":
        encrypt(password, args.output or Path("adc.enc"), args.input or ADC_PATH)
    elif args.option == "decrypt":
        decrypt(password, args.input or Path("adc.enc"), args.output or ADC_PATH)
    elif args.option == "upload":
        upload(password, args.input or ADC_PATH)
    elif args.option == "download":
        download(password, args.output or ADC_PATH)


if __name__ == "__main__":
    main()