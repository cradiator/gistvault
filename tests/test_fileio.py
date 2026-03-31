from __future__ import annotations

import stat
from pathlib import Path

import pytest

import gistvault.gistvault as gistvault


def test_read_source(tmp_path: Path) -> None:
    f = tmp_path / "test.json"
    f.write_text('{"key": "value"}')
    assert gistvault._read_source(f) == b'{"key": "value"}'


def test_read_source_missing(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        gistvault._read_source(tmp_path / "missing.json")


def test_write_output(tmp_path: Path) -> None:
    dst = tmp_path / "out.json"
    gistvault._write_output(dst, b"content")
    assert dst.read_bytes() == b"content"
    assert stat.S_IMODE(dst.stat().st_mode) == 0o600


def test_write_output_creates_parents(tmp_path: Path) -> None:
    dst = tmp_path / "a" / "b" / "out.json"
    gistvault._write_output(dst, b"content")
    assert dst.read_bytes() == b"content"


def test_write_output_backs_up_existing(tmp_path: Path) -> None:
    dst = tmp_path / "out.json"
    dst.write_text("old")
    gistvault._write_output(dst, b"new")
    assert dst.read_bytes() == b"new"
    backups = list(tmp_path.glob("out.json.bak.*"))
    assert len(backups) == 1
    assert backups[0].read_text() == "old"
