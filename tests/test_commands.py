from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

import gistvault


def test_encrypt_decrypt_roundtrip(sample_file: Path, tmp_path: Path) -> None:
    enc = tmp_path / "encrypted.enc"
    dec = tmp_path / "decrypted.json"

    gistvault.encrypt("pw123", enc, sample_file)
    assert enc.exists()

    gistvault.decrypt("pw123", enc, dec)
    assert dec.read_text() == '{"secret": true}'


def test_decrypt_wrong_password(sample_file: Path, tmp_path: Path) -> None:
    enc = tmp_path / "encrypted.enc"
    gistvault.encrypt("right", enc, sample_file)
    with pytest.raises(SystemExit):
        gistvault.decrypt("wrong", enc, tmp_path / "out.json")


def test_decrypt_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        gistvault.decrypt("pw", tmp_path / "nope.enc", tmp_path / "out.json")


def test_encrypt_missing_source(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        gistvault.encrypt("pw", tmp_path / "out.enc", tmp_path / "nope.json")


def test_decrypt_uses_saved_output(
    sample_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    enc = tmp_path / "encrypted.enc"
    gistvault.encrypt("pw", enc, sample_file)

    monkeypatch.setattr("builtins.input", lambda _: "y")
    gistvault.decrypt("pw", enc, None)
    assert sample_file.read_text() == '{"secret": true}'


def test_decrypt_aborts_on_no(
    sample_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    enc = tmp_path / "encrypted.enc"
    gistvault.encrypt("pw", enc, sample_file)

    monkeypatch.setattr("builtins.input", lambda _: "n")
    with pytest.raises(SystemExit):
        gistvault.decrypt("pw", enc, None)


def test_envelope_contains_metadata(sample_file: Path, tmp_path: Path) -> None:
    enc = tmp_path / "encrypted.enc"
    gistvault.encrypt("pw", enc, sample_file)

    envelope = gistvault._decrypt_blob("pw", enc.read_text())
    assert all(k in envelope for k in ("input", "output", "timestamp", "data"))


def test_upload_creates_new(
    sample_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_request(
        method: str, url: str, token: str, data: dict[str, Any] | None = None
    ) -> dict[str, str]:
        calls.append((method, url))
        return {"id": "new123"}

    monkeypatch.setattr(gistvault, "_gist_token", lambda: "tok")
    monkeypatch.setattr(gistvault, "_find_gist", lambda *a: None)
    monkeypatch.setattr(gistvault, "_github_request", fake_request)

    gistvault.upload("pw", sample_file)
    assert calls[0][0] == "POST"


def test_upload_updates_existing(
    sample_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_request(
        method: str, url: str, token: str, data: dict[str, Any] | None = None
    ) -> dict[str, str]:
        calls.append((method, url))
        return {}

    monkeypatch.setattr(gistvault, "_gist_token", lambda: "tok")
    monkeypatch.setattr(
        gistvault, "_find_gist", lambda *a: {"id": "exist", "url": "http://x"}
    )
    monkeypatch.setattr(gistvault, "_github_request", fake_request)

    gistvault.upload("pw", sample_file)
    assert calls[0][0] == "PATCH"


def test_download_no_gist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(gistvault, "_gist_token", lambda: "tok")
    monkeypatch.setattr(gistvault, "_find_gist", lambda *a, **kw: None)
    with pytest.raises(SystemExit):
        gistvault.download("pw", tmp_path / "out.json")


def test_download_with_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = tmp_path / "orig.json"
    plaintext = b'{"secret": true}'
    blob = gistvault._encrypt_blob("pw", plaintext, input_path=src, output_path=src)
    gist = {"files": {gistvault.GIST_FILENAME: {"content": blob}}}

    monkeypatch.setattr(gistvault, "_gist_token", lambda: "tok")
    monkeypatch.setattr(gistvault, "_find_gist", lambda *a, **kw: gist)

    dst = tmp_path / "out.json"
    gistvault.download("pw", dst)
    assert dst.read_bytes() == plaintext


def test_download_with_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = tmp_path / "orig.json"
    plaintext = b'{"secret": true}'
    blob = gistvault._encrypt_blob("pw", plaintext, input_path=src, output_path=src)
    gist = {"files": {gistvault.GIST_FILENAME: {"content": blob}}}

    monkeypatch.setattr(gistvault, "_gist_token", lambda: "tok")
    monkeypatch.setattr(gistvault, "_find_gist", lambda *a, **kw: gist)
    monkeypatch.setattr("builtins.input", lambda _: "y")

    gistvault.download("pw", None)
    assert src.read_bytes() == plaintext


def test_download_aborts_on_no(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = tmp_path / "orig.json"
    plaintext = b'{"secret": true}'
    blob = gistvault._encrypt_blob("pw", plaintext, input_path=src, output_path=src)
    gist = {"files": {gistvault.GIST_FILENAME: {"content": blob}}}

    monkeypatch.setattr(gistvault, "_gist_token", lambda: "tok")
    monkeypatch.setattr(gistvault, "_find_gist", lambda *a, **kw: gist)
    monkeypatch.setattr("builtins.input", lambda _: "n")

    with pytest.raises(SystemExit):
        gistvault.download("pw", None)
