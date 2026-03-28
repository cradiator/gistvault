from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture()
def sample_file(tmp_path: Path) -> Path:
    f = tmp_path / "secret.json"
    f.write_text('{"secret": true}')
    return f
