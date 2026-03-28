#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "cryptography>=42.0",
# ]
# ///
"""
Encrypted secret storage backed by GitHub Gists.

Commands:
    encrypt   Encrypt a local file.
    decrypt   Decrypt a local encrypted file.
    upload    Encrypt and upload a file to a GitHub Gist.
    download  Download and decrypt a file from a GitHub Gist.
    list      List all encrypted files stored in GitHub Gists.
    delete    Delete an encrypted file from GitHub Gists.

Usage examples:
    # Encrypt a file locally
    ./gistvault.py encrypt -p mypass -i secret.json -o secret.enc

    # Decrypt a local file (explicit output)
    ./gistvault.py decrypt -p mypass -i secret.enc -o secret.json

    # Decrypt using the saved output path (prompts for confirmation)
    ./gistvault.py decrypt -p mypass -i secret.enc

    # Upload a file (encrypted as secret.json.enc in a secret gist)
    ./gistvault.py upload -p mypass -i secret.json

    # Re-upload updates the existing gist automatically
    ./gistvault.py upload -p mypass -i secret.json

    # List all stored files
    ./gistvault.py list

    # Download by name (prompts for output path if --output omitted)
    ./gistvault.py download -p mypass -n secret.json
    ./gistvault.py download -p mypass -n secret.json -o ~/restored.json

    # Delete a stored file (prompts for confirmation)
    ./gistvault.py delete -n secret.json

Notes:
    - If --password is omitted, you will be prompted securely.
    - upload/download/list/delete require GISTVAULT_TOKEN env var
      (GitHub personal access token with 'gist' scope).
    - Each uploaded file is stored as a separate secret (unlisted) gist.
    - The gist filename is <input_name>.enc (e.g. secret.json -> secret.json.enc).
    - Encrypted files embed the original input/output paths. When downloading
      without --output, the saved path is shown for confirmation.
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


def main() -> None:
    p = argparse.ArgumentParser(
        description="Encrypted secret storage backed by GitHub Gists.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "commands:\n"
            "  encrypt   Encrypt a local file             (requires -i, -o)\n"
            "  decrypt   Decrypt a local encrypted file   (requires -i; -o optional)\n"
            "  upload    Encrypt and push to GitHub Gist   (requires -i; --new-name optional)\n"
            "  download  Pull from GitHub Gist and decrypt (requires -n; -o optional)\n"
            "  list      List all encrypted gist entries\n"
            "  delete    Delete an encrypted gist entry    (requires -n)\n"
            "  rename    Rename a gist entry               (requires -n, --new-name)\n"
            "\n"
            "environment:\n"
            "  GISTVAULT_TOKEN  GitHub PAT with 'gist' scope (required for gist commands)"
        ),
    )
    p.add_argument("option", nargs="?", default=None,
                   choices=["encrypt", "decrypt", "upload", "download", "list", "delete", "rename"],
                   metavar="command",
                   help="{encrypt,decrypt,upload,download,list,delete,rename}")
    p.add_argument("-p", "--password",
                   help="encryption password (omit to be prompted securely)")
    p.add_argument("-i", "--input", type=Path, default=None,
                   help="input file path (encrypt/upload: plaintext source; "
                        "decrypt: encrypted file)")
    p.add_argument("-o", "--output", type=Path, default=None,
                   help="output file path (encrypt: encrypted file; "
                        "decrypt/download: plaintext destination)")
    p.add_argument("-n", "--name", default=None,
                   help="gist entry name for download/delete/rename "
                        "(e.g. 'secret.json' or 'secret.json.enc')")
    p.add_argument("--new-name", default=None,
                   help="new name (upload: override gist filename; "
                        "rename: target name)")
    args = p.parse_args()

    if not args.option:
        p.print_help()
        return

    if args.option == "list":
        list_gists()
        return
    if args.option == "delete":
        if not args.name:
            p.error("delete requires --name")
        delete(args.name)
        return
    if args.option == "rename":
        if not args.name or not args.new_name:
            p.error("rename requires --name and --new-name")
        rename(args.name, args.new_name)
        return

    # Validate required params before prompting for password
    missing: list[str] = []
    if args.option == "encrypt":
        if not args.input:
            missing.append("--input")
        if not args.output:
            missing.append("--output")
    elif args.option == "decrypt":
        if not args.input:
            missing.append("--input")
    elif args.option == "upload":
        if not args.input:
            missing.append("--input")
    elif args.option == "download":
        if not args.name:
            missing.append("--name")
    if missing:
        p.error(f"{args.option} requires {', '.join(missing)}")

    password = args.password or getpass.getpass("Password: ")
    if not password:
        sys.exit("Password cannot be empty.")

    if args.option in ("encrypt", "upload") and not args.password:
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            sys.exit("Passwords do not match.")

    if args.option == "encrypt":
        encrypt(password, args.output, args.input)
    elif args.option == "decrypt":
        decrypt(password, args.input, args.output)
    elif args.option == "upload":
        upload(password, args.input, args.new_name)
    elif args.option == "download":
        download(password, args.name, args.output)


if __name__ == "__main__":
    main()