import json
from conftest import EXAMPLES
from vigil import dashboard as dash_mod
from vigil import sbom as sbom_mod
from vigil import timeline as tl_mod


def test_dashboard_builds(tmp_path):
    import shutil
    (tmp_path / "a").mkdir()
    shutil.copy(EXAMPLES / "clean-repo" / "AGENTS.md", tmp_path / "a" / "AGENTS.md")
    page = dash_mod.build(tmp_path)
    assert "dashboard" in page and "100/100" in page


def test_sbom_shape():
    doc = sbom_mod.build(EXAMPLES / "clean-repo")
    assert doc["bomFormat"] == "agentvigil-sbom"
    assert doc["trust"]["score"] == 100
    assert any(c["name"] == "AGENTS.md" for c in doc["components"])


def test_timeline_graceful_outside_repo(tmp_path):
    assert tl_mod.timeline(tmp_path) == []
