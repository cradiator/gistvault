from __future__ import annotations

from typing import Any

import pytest

import gistvault.gistvault as gistvault

_TEST_FILENAME = "secret.json.enc"


def test_gist_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GISTVAULT_TOKEN", "ghp_test123")
    assert gistvault._gist_token() == "ghp_test123"


def test_gist_token_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GISTVAULT_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        gistvault._gist_token()


def test_gist_filename_appends_enc() -> None:
    assert gistvault._gist_filename("secret.json") == "secret.json.enc"


def test_gist_filename_no_double_enc() -> None:
    assert gistvault._gist_filename("secret.json.enc") == "secret.json.enc"


def _make_gist_pages(
    pages: list[list[dict[str, Any]]],
) -> Any:
    page_iter = iter(pages)

    def fake_request(
        method: str, url: str, token: str, data: dict[str, Any] | None = None
    ) -> Any:
        if "/gists?" in url:
            return next(page_iter, [])
        return {"files": {_TEST_FILENAME: {"content": "blob"}}}

    return fake_request


_SAMPLE_GIST: dict[str, Any] = {
    "id": "abc",
    "url": "https://api.github.com/gists/abc",
    "description": gistvault.GIST_DESCRIPTION,
    "files": {_TEST_FILENAME: {}},
}


def test_find_gist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gistvault, "_github_request", _make_gist_pages([[_SAMPLE_GIST]])
    )
    result = gistvault._find_gist("token", _TEST_FILENAME)
    assert result is not None
    assert result["id"] == "abc"


def test_find_gist_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gistvault, "_github_request", _make_gist_pages([[]]))
    assert gistvault._find_gist("token", _TEST_FILENAME) is None


def test_find_gist_full(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gistvault, "_github_request", _make_gist_pages([[_SAMPLE_GIST]])
    )
    result = gistvault._find_gist("token", _TEST_FILENAME, full=True)
    assert result is not None
    assert "content" in result["files"][_TEST_FILENAME]


def test_find_all_gists(monkeypatch: pytest.MonkeyPatch) -> None:
    other_gist: dict[str, Any] = {
        "id": "other",
        "description": "not-gistvault",
        "files": {"other.txt": {}},
    }
    monkeypatch.setattr(
        gistvault, "_github_request",
        _make_gist_pages([[_SAMPLE_GIST, other_gist]])
    )
    result = gistvault._find_all_gists("token")
    assert len(result) == 1
    assert result[0]["id"] == "abc"


def test_list_gists(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(gistvault, "_gist_token", lambda: "tok")
    monkeypatch.setattr(gistvault, "_find_all_gists", lambda _: [
        {"id": "abc", "updated_at": "2026-03-28", "files": {_TEST_FILENAME: {}}},
    ])
    gistvault.list_gists()
    out = capsys.readouterr().out
    assert _TEST_FILENAME in out
    assert "abc" in out


def test_list_gists_empty(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(gistvault, "_gist_token", lambda: "tok")
    monkeypatch.setattr(gistvault, "_find_all_gists", lambda _: [])
    gistvault.list_gists()
    out = capsys.readouterr().out
    assert "No gistvault entries found" in out
