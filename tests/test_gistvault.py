from __future__ import annotations

import base64
import os
import stat
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import gistvault


class TestDeriveKey:
    def test_deterministic(self) -> None:
        salt = os.urandom(gistvault.SALT_LEN)
        k1 = gistvault.derive_key("pass", salt)
        k2 = gistvault.derive_key("pass", salt)
        assert k1 == k2

    def test_different_salt(self) -> None:
        k1 = gistvault.derive_key("pass", b"\x00" * gistvault.SALT_LEN)
        k2 = gistvault.derive_key("pass", b"\x01" * gistvault.SALT_LEN)
        assert k1 != k2

    def test_different_password(self) -> None:
        salt = os.urandom(gistvault.SALT_LEN)
        k1 = gistvault.derive_key("pass1", salt)
        k2 = gistvault.derive_key("pass2", salt)
        assert k1 != k2


class TestCompactExpandPath:
    def test_compact_home_path(self) -> None:
        p = Path.home() / "Documents" / "secret.json"
        assert gistvault._compact_path(p) == "~/Documents/secret.json"

    def test_compact_non_home_path(self) -> None:
        p = Path("/etc/config.json")
        result = gistvault._compact_path(p)
        assert not result.startswith("~/")
        assert result == str(p.resolve())

    def test_expand_tilde(self) -> None:
        result = gistvault._expand_path("~/Documents/secret.json")
        assert result == Path.home() / "Documents" / "secret.json"

    def test_expand_absolute(self) -> None:
        result = gistvault._expand_path("/etc/config.json")
        assert result == Path("/etc/config.json")


class TestEncryptDecryptBlob:
    def test_roundtrip(self, tmp_path: Path) -> None:
        src = tmp_path / "test.json"
        dst = tmp_path / "out.json"
        plaintext = b"hello world"
        blob = gistvault._encrypt_blob("mypass", plaintext,
                                       input_path=src, output_path=dst)
        envelope = gistvault._decrypt_blob("mypass", blob)
        assert base64.b64decode(envelope["data"]) == plaintext
        assert "input" in envelope
        assert "output" in envelope
        assert "timestamp" in envelope

    def test_wrong_password(self, tmp_path: Path) -> None:
        blob = gistvault._encrypt_blob("right", b"secret",
                                       input_path=tmp_path / "a",
                                       output_path=tmp_path / "b")
        with pytest.raises(SystemExit):
            gistvault._decrypt_blob("wrong", blob)

    def test_invalid_base64(self) -> None:
        with pytest.raises(SystemExit):
            gistvault._decrypt_blob("pass", "not-valid-base64!!!")

    def test_too_short(self) -> None:
        short = base64.b64encode(b"\x00" * gistvault.SALT_LEN).decode()
        with pytest.raises(SystemExit):
            gistvault._decrypt_blob("pass", short)


class TestReadSource:
    def test_reads_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.json"
        f.write_text('{"key": "value"}')
        assert gistvault._read_source(f) == b'{"key": "value"}'

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            gistvault._read_source(tmp_path / "missing.json")


class TestWriteOutput:
    def test_writes_file(self, tmp_path: Path) -> None:
        dst = tmp_path / "out.json"
        gistvault._write_output(dst, b"content")
        assert dst.read_bytes() == b"content"
        assert stat.S_IMODE(dst.stat().st_mode) == 0o600

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        dst = tmp_path / "a" / "b" / "out.json"
        gistvault._write_output(dst, b"content")
        assert dst.read_bytes() == b"content"

    def test_backs_up_existing(self, tmp_path: Path) -> None:
        dst = tmp_path / "out.json"
        dst.write_text("old")
        gistvault._write_output(dst, b"new")
        assert dst.read_bytes() == b"new"
        backups = list(tmp_path.glob("out.json.bak.*"))
        assert len(backups) == 1
        assert backups[0].read_text() == "old"


class TestEncryptDecryptFile:
    def test_roundtrip(self, tmp_path: Path) -> None:
        src = tmp_path / "plain.json"
        src.write_text('{"secret": true}')
        enc = tmp_path / "encrypted.enc"
        dec = tmp_path / "decrypted.json"

        gistvault.encrypt("pw123", enc, src)
        assert enc.exists()

        gistvault.decrypt("pw123", enc, dec)
        assert dec.read_text() == '{"secret": true}'

    def test_decrypt_wrong_password(self, tmp_path: Path) -> None:
        src = tmp_path / "plain.json"
        src.write_text("data")
        enc = tmp_path / "encrypted.enc"

        gistvault.encrypt("right", enc, src)
        with pytest.raises(SystemExit):
            gistvault.decrypt("wrong", enc, tmp_path / "out.json")

    def test_decrypt_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            gistvault.decrypt("pw", tmp_path / "nope.enc", tmp_path / "out.json")

    def test_encrypt_missing_source(self, tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            gistvault.encrypt("pw", tmp_path / "out.enc", tmp_path / "nope.json")

    def test_decrypt_uses_saved_output(self, tmp_path: Path) -> None:
        src = tmp_path / "plain.json"
        src.write_text("secret data")
        enc = tmp_path / "encrypted.enc"
        gistvault.encrypt("pw", enc, src)

        with patch("builtins.input", return_value="y"):
            gistvault.decrypt("pw", enc, None)
        assert src.read_text() == "secret data"

    def test_decrypt_aborts_on_no(self, tmp_path: Path) -> None:
        src = tmp_path / "plain.json"
        src.write_text("secret data")
        enc = tmp_path / "encrypted.enc"
        gistvault.encrypt("pw", enc, src)

        with patch("builtins.input", return_value="n"), pytest.raises(SystemExit):
            gistvault.decrypt("pw", enc, None)

    def test_envelope_contains_metadata(self, tmp_path: Path) -> None:
        src = tmp_path / "plain.json"
        src.write_text("data")
        enc = tmp_path / "encrypted.enc"
        gistvault.encrypt("pw", enc, src)

        envelope = gistvault._decrypt_blob("pw", enc.read_text())
        assert "input" in envelope
        assert "output" in envelope
        assert "timestamp" in envelope
        assert "data" in envelope


class TestGistToken:
    def test_returns_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GISTVAULT_TOKEN", "ghp_test123")
        assert gistvault._gist_token() == "ghp_test123"

    def test_missing_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GISTVAULT_TOKEN", raising=False)
        with pytest.raises(SystemExit):
            gistvault._gist_token()


class TestFindGist:
    def _mock_gists(self, gists: list[list[dict[str, Any]]]) -> MagicMock:
        pages = iter(gists)
        def side_effect(method: str, url: str, token: str, data: dict[str, Any] | None = None) -> Any:
            if "/gists?" in url:
                return next(pages, [])
            return {"files": {gistvault.GIST_FILENAME: {"content": "blob"}}}
        return MagicMock(side_effect=side_effect)

    @patch("gistvault._github_request")
    def test_finds_gist(self, mock_req: MagicMock) -> None:
        mock_req.side_effect = self._mock_gists([
            [{"id": "abc", "url": "https://api.github.com/gists/abc",
              "files": {gistvault.GIST_FILENAME: {}}}]
        ]).side_effect
        result = gistvault._find_gist("token")
        assert result is not None
        assert result["id"] == "abc"

    @patch("gistvault._github_request")
    def test_no_gist(self, mock_req: MagicMock) -> None:
        mock_req.return_value = []
        result = gistvault._find_gist("token")
        assert result is None

    @patch("gistvault._github_request")
    def test_full_fetch(self, mock_req: MagicMock) -> None:
        mock_req.side_effect = self._mock_gists([
            [{"id": "abc", "url": "https://api.github.com/gists/abc",
              "files": {gistvault.GIST_FILENAME: {}}}]
        ]).side_effect
        result = gistvault._find_gist("token", full=True)
        assert result is not None
        assert "content" in result["files"][gistvault.GIST_FILENAME]


class TestUpload:
    @patch("gistvault._find_gist", return_value=None)
    @patch("gistvault._github_request", return_value={"id": "new123"})
    @patch("gistvault._gist_token", return_value="tok")
    def test_creates_new(self, _tok: MagicMock, mock_req: MagicMock,
                         _find: MagicMock, tmp_path: Path) -> None:
        src = tmp_path / "cred.json"
        src.write_text('{"key": "val"}')
        gistvault.upload("pw", src)
        mock_req.assert_called_once()
        assert mock_req.call_args[0][0] == "POST"

    @patch("gistvault._find_gist", return_value={"id": "exist", "url": "http://x"})
    @patch("gistvault._github_request", return_value={})
    @patch("gistvault._gist_token", return_value="tok")
    def test_updates_existing(self, _tok: MagicMock, mock_req: MagicMock,
                              _find: MagicMock, tmp_path: Path) -> None:
        src = tmp_path / "cred.json"
        src.write_text('{"key": "val"}')
        gistvault.upload("pw", src)
        assert mock_req.call_args[0][0] == "PATCH"


class TestDownload:
    @patch("gistvault._find_gist", return_value=None)
    @patch("gistvault._gist_token", return_value="tok")
    def test_no_gist(self, _tok: MagicMock, _find: MagicMock,
                     tmp_path: Path) -> None:
        with pytest.raises(SystemExit):
            gistvault.download("pw", tmp_path / "out.json")

    @patch("gistvault._gist_token", return_value="tok")
    def test_downloads_with_output(self, _tok: MagicMock, tmp_path: Path) -> None:
        src = tmp_path / "orig.json"
        plaintext = b'{"secret": true}'
        blob = gistvault._encrypt_blob("pw", plaintext,
                                       input_path=src, output_path=src)
        gist = {"files": {gistvault.GIST_FILENAME: {"content": blob}}}
        with patch("gistvault._find_gist", return_value=gist):
            dst = tmp_path / "out.json"
            gistvault.download("pw", dst)
            assert dst.read_bytes() == plaintext

    @patch("gistvault._gist_token", return_value="tok")
    def test_downloads_with_confirmation(self, _tok: MagicMock, tmp_path: Path) -> None:
        src = tmp_path / "orig.json"
        plaintext = b'{"secret": true}'
        blob = gistvault._encrypt_blob("pw", plaintext,
                                       input_path=src, output_path=src)
        gist = {"files": {gistvault.GIST_FILENAME: {"content": blob}}}
        with patch("gistvault._find_gist", return_value=gist), \
             patch("builtins.input", return_value="y"):
            gistvault.download("pw", None)
            assert src.read_bytes() == plaintext

    @patch("gistvault._gist_token", return_value="tok")
    def test_downloads_abort_on_no(self, _tok: MagicMock, tmp_path: Path) -> None:
        src = tmp_path / "orig.json"
        plaintext = b'{"secret": true}'
        blob = gistvault._encrypt_blob("pw", plaintext,
                                       input_path=src, output_path=src)
        gist = {"files": {gistvault.GIST_FILENAME: {"content": blob}}}
        with patch("gistvault._find_gist", return_value=gist), \
             patch("builtins.input", return_value="n"), \
             pytest.raises(SystemExit):
            gistvault.download("pw", None)
