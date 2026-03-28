from __future__ import annotations

from typing import Any

import pytest

import gistvault


def test_gist_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GISTVAULT_TOKEN", "ghp_test123")
    assert gistvault._gist_token() == "ghp_test123"


def test_gist_token_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GISTVAULT_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        gistvault._gist_token()


def _make_gist_pages(
    pages: list[list[dict[str, Any]]],
) -> Any:
    page_iter = iter(pages)

    def fake_request(
        method: str, url: str, token: str, data: dict[str, Any] | None = None
    ) -> Any:
        if "/gists?" in url:
            return next(page_iter, [])
        return {"files": {gistvault.GIST_FILENAME: {"content": "blob"}}}

    return fake_request


_SAMPLE_GIST: dict[str, Any] = {
    "id": "abc",
    "url": "https://api.github.com/gists/abc",
    "files": {gistvault.GIST_FILENAME: {}},
}


def test_find_gist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gistvault, "_github_request", _make_gist_pages([[_SAMPLE_GIST]])
    )
    result = gistvault._find_gist("token")
    assert result is not None
    assert result["id"] == "abc"


def test_find_gist_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gistvault, "_github_request", _make_gist_pages([[]]))
    assert gistvault._find_gist("token") is None


def test_find_gist_full(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        gistvault, "_github_request", _make_gist_pages([[_SAMPLE_GIST]])
    )
    result = gistvault._find_gist("token", full=True)
    assert result is not None
    assert "content" in result["files"][gistvault.GIST_FILENAME]
