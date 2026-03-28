#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "cryptography>=42.0",
#     "typer>=0.9.0",
# ]
# ///
"""Encrypted secret storage backed by GitHub Gists."""

from __future__ import annotations

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
from typing import Annotated, Any, Optional

import typer

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_LEN = 16
GIST_ENC_SUFFIX = ".enc"
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
            body_bytes = resp.read()
            if not body_bytes:
                return {}
            return json.loads(body_bytes)
    except urllib.error.HTTPError as e:
        sys.exit(f"GitHub API error {e.code}: {e.read().decode()}")


def _gist_filename(name: str) -> str:
    if name.endswith(GIST_ENC_SUFFIX):
        return name
    return name + GIST_ENC_SUFFIX


def _find_gist(token: str, filename: str, full: bool = False) -> dict[str, Any] | None:
    page = 1
    while True:
        gists: list[dict[str, Any]] = _github_request(
            "GET", f"{GITHUB_API}/gists?per_page=100&page={page}", token)
        if not gists:
            return None
        for g in gists:
            if g.get("description") == GIST_DESCRIPTION and filename in g.get("files", {}):
                if full:
                    result: dict[str, Any] = _github_request("GET", g["url"], token)
                    return result
                return g
        page += 1


def _find_all_gists(token: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    page = 1
    while True:
        gists: list[dict[str, Any]] = _github_request(
            "GET", f"{GITHUB_API}/gists?per_page=100&page={page}", token)
        if not gists:
            break
        for g in gists:
            if g.get("description") == GIST_DESCRIPTION:
                found.append(g)
        page += 1
    return found


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


def upload(password: str, src: Path, name: str | None = None) -> None:
    plaintext = _read_source(src)
    filename = _gist_filename(name or src.name)
    blob = _encrypt_blob(password, plaintext, input_path=src, output_path=src)
    gh_token = _gist_token()
    existing = _find_gist(gh_token, filename)
    payload: dict[str, Any] = {
        "description": GIST_DESCRIPTION,
        "files": {filename: {"content": blob}},
    }
    if existing:
        _github_request("PATCH", existing["url"], gh_token, payload)
        print(f"Updated gist {existing['id']} ({filename})")
    else:
        payload["public"] = False
        result = _github_request("POST", f"{GITHUB_API}/gists", gh_token, payload)
        print(f"Created gist {result['id']} ({filename})")


def download(password: str, name: str, dst: Path | None) -> None:
    filename = _gist_filename(name)
    gh_token = _gist_token()
    gist = _find_gist(gh_token, filename, full=True)
    if not gist:
        sys.exit(f"No gist found with file '{filename}'.")
    envelope = _decrypt_blob(password, gist["files"][filename]["content"])
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
    print(f"Decrypted {filename} -> {dst}")


def list_gists() -> None:
    gh_token = _gist_token()
    gists = _find_all_gists(gh_token)
    if not gists:
        print("No gistvault entries found.")
        return
    for g in gists:
        files = list(g.get("files", {}).keys())
        updated = g.get("updated_at", "")
        for f in files:
            print(f"  {f}  (gist: {g['id']}, updated: {updated})")


def rename(old_name: str, new_name: str) -> None:
    old_filename = _gist_filename(old_name)
    new_filename = _gist_filename(new_name)
    gh_token = _gist_token()
    gist = _find_gist(gh_token, old_filename, full=True)
    if not gist:
        sys.exit(f"No gist found with file '{old_filename}'.")
    content = gist["files"][old_filename]["content"]
    payload: dict[str, Any] = {
        "files": {
            old_filename: {"filename": new_filename, "content": content},
        },
    }
    _github_request("PATCH", gist["url"], gh_token, payload)
    print(f"Renamed {old_filename} -> {new_filename}")


def delete(name: str) -> None:
    filename = _gist_filename(name)
    gh_token = _gist_token()
    gist = _find_gist(gh_token, filename)
    if not gist:
        sys.exit(f"No gist found with file '{filename}'.")
    confirm = input(f"Delete {filename} (gist: {gist['id']})? [y/N] ").strip().lower()
    if confirm != "y":
        sys.exit("Aborted.")
    _github_request("DELETE", gist["url"], gh_token)
    print(f"Deleted {filename} (gist: {gist['id']})")


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


app = typer.Typer(
    help="Encrypted secret storage backed by GitHub Gists.\n\n"
         "Environment: GISTVAULT_TOKEN — GitHub PAT with 'gist' scope "
         "(required for gist commands).",
    no_args_is_help=True,
    add_completion=False,
)

def _get_password(password: str | None, confirm: bool = False) -> str:
    if password is not None:
        return password
    pw = getpass.getpass("Password: ")
    if not pw:
        sys.exit("Password cannot be empty.")
    if confirm:
        c = getpass.getpass("Confirm password: ")
        if pw != c:
            sys.exit("Passwords do not match.")
    return pw


@app.command(name="encrypt")
def cmd_encrypt(
    input: Annotated[Path, typer.Option("--input", "-i", help="Plaintext source file.")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Encrypted output file.")],
    password: Annotated[Optional[str], typer.Option("--password", "-p", help="Encryption password (omit to be prompted).")] = None,
) -> None:
    """Encrypt a local file."""
    pw = _get_password(password, confirm=True)
    encrypt(pw, output, input)


@app.command(name="decrypt")
def cmd_decrypt(
    input: Annotated[Path, typer.Option("--input", "-i", help="Encrypted file to decrypt.")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output path (uses saved path if omitted).")] = None,
    password: Annotated[Optional[str], typer.Option("--password", "-p", help="Encryption password (omit to be prompted).")] = None,
) -> None:
    """Decrypt a local encrypted file."""
    pw = _get_password(password)
    decrypt(pw, input, output)


@app.command(name="upload")
def cmd_upload(
    input: Annotated[Path, typer.Option("--input", "-i", help="Plaintext file to encrypt and upload.")],
    password: Annotated[Optional[str], typer.Option("--password", "-p", help="Encryption password (omit to be prompted).")] = None,
    new_name: Annotated[Optional[str], typer.Option("--new-name", help="Override gist filename.")] = None,
) -> None:
    """Encrypt and upload a file to a GitHub Gist."""
    pw = _get_password(password, confirm=True)
    upload(pw, input, new_name)


@app.command(name="download")
def cmd_download(
    name: Annotated[str, typer.Option("--name", "-n", help="Gist entry name.")],
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output path (uses saved path if omitted).")] = None,
    password: Annotated[Optional[str], typer.Option("--password", "-p", help="Encryption password (omit to be prompted).")] = None,
) -> None:
    """Download and decrypt a file from a GitHub Gist."""
    pw = _get_password(password)
    download(pw, name, output)


@app.command(name="list")
def cmd_list() -> None:
    """List all encrypted files stored in GitHub Gists."""
    list_gists()


@app.command(name="delete")
def cmd_delete(
    name: Annotated[str, typer.Option("--name", "-n", help="Gist entry name to delete.")],
) -> None:
    """Delete an encrypted file from GitHub Gists."""
    delete(name)


@app.command(name="rename")
def cmd_rename(
    name: Annotated[str, typer.Option("--name", "-n", help="Current gist entry name.")],
    new_name: Annotated[str, typer.Option("--new-name", help="New name for the gist entry.")],
) -> None:
    """Rename a gist entry."""
    rename(name, new_name)


if __name__ == "__main__":
    app()