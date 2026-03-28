from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

import gistvault


def test_derive_key_deterministic() -> None:
    salt = os.urandom(gistvault.SALT_LEN)
    assert gistvault.derive_key("pass", salt) == gistvault.derive_key("pass", salt)


def test_derive_key_different_salt() -> None:
    k1 = gistvault.derive_key("pass", b"\x00" * gistvault.SALT_LEN)
    k2 = gistvault.derive_key("pass", b"\x01" * gistvault.SALT_LEN)
    assert k1 != k2


def test_derive_key_different_password() -> None:
    salt = os.urandom(gistvault.SALT_LEN)
    assert gistvault.derive_key("pass1", salt) != gistvault.derive_key("pass2", salt)


def test_compact_path_home() -> None:
    p = Path.home() / "Documents" / "secret.json"
    assert gistvault._compact_path(p) == "~/Documents/secret.json"


def test_compact_path_non_home() -> None:
    p = Path("/etc/config.json")
    result = gistvault._compact_path(p)
    assert not result.startswith("~/")
    assert result == str(p.resolve())


def test_expand_path_tilde() -> None:
    assert gistvault._expand_path("~/Documents/secret.json") == (
        Path.home() / "Documents" / "secret.json"
    )


def test_expand_path_absolute() -> None:
    assert gistvault._expand_path("/etc/config.json") == Path("/etc/config.json")


def test_encrypt_decrypt_blob_roundtrip(tmp_path: Path) -> None:
    plaintext = b"hello world"
    blob = gistvault._encrypt_blob(
        "mypass", plaintext, input_path=tmp_path / "in", output_path=tmp_path / "out"
    )
    envelope = gistvault._decrypt_blob("mypass", blob)
    assert base64.b64decode(envelope["data"]) == plaintext
    assert "input" in envelope
    assert "output" in envelope
    assert "timestamp" in envelope


def test_decrypt_blob_wrong_password(tmp_path: Path) -> None:
    blob = gistvault._encrypt_blob(
        "right", b"secret", input_path=tmp_path / "a", output_path=tmp_path / "b"
    )
    with pytest.raises(SystemExit):
        gistvault._decrypt_blob("wrong", blob)


def test_decrypt_blob_invalid_base64() -> None:
    with pytest.raises(SystemExit):
        gistvault._decrypt_blob("pass", "not-valid-base64!!!")


def test_decrypt_blob_too_short() -> None:
    short = base64.b64encode(b"\x00" * gistvault.SALT_LEN).decode()
    with pytest.raises(SystemExit):
        gistvault._decrypt_blob("pass", short)
