import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vigil.surface import SurfaceFile  # noqa: E402


@pytest.fixture
def surface_file():
    def _make(path: str, text: str, kind: str = "agent_rules") -> SurfaceFile:
        return SurfaceFile(path=path, kind=kind, data=text.encode("utf-8"))

    return _make


@pytest.fixture
def repo(tmp_path):
    """A minimal repo with one rules file; returns (root, path)."""

    def _make(text: str, name: str = "AGENTS.md"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return tmp_path, path

    return _make


def tag_encode(payload: str) -> str:
    """Encode ASCII as invisible Unicode tag characters (U+E0000 + ord)."""
    return "".join(chr(0xE0000 + ord(ch)) for ch in payload)


EXAMPLES = ROOT / "examples"
