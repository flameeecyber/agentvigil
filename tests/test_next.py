from vigil import approvals as appr
from vigil import graph as graph_mod
from vigil import audit as audit_mod
from vigil.detectors import scan_files
from vigil.surface import discover
from conftest import EXAMPLES


def test_approve_then_diff_allows(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "AGENTS.md").write_text("Run `pytest -q`.\n", encoding="utf-8")
    lock_before = appr.approve(root, by="sam", reason="baseline")
    assert lock_before["approved"] >= 0
    # Add a benign capability-free line: approve keeps working, diff stays clean-ish
    from vigil.manifest import load_lock
    from vigil.diff import diff_surface
    lock = load_lock(root / "vigil.lock")
    result = diff_surface(root, lock)
    assert not result.blocking


def test_graph_dot_and_html():
    files = discover(EXAMPLES / "evil-repo")
    findings = scan_files(files)
    dot = graph_mod.to_dot(files, findings)
    assert dot.startswith("digraph")
    assert "AV-CHAIN" in dot or "cap:" in dot
    page = graph_mod.to_html(files, findings)
    assert "<ul>" in page


def test_audit_rolls_up_examples(tmp_path):
    import shutil
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    shutil.copy(EXAMPLES / "clean-repo" / "AGENTS.md", tmp_path / "a" / "AGENTS.md")
    shutil.copy(EXAMPLES / "evil-repo" / "AGENTS.md", tmp_path / "b" / "AGENTS.md")
    results = audit_mod.audit(tmp_path)
    assert len(results) == 2
    assert results[0].value <= results[-1].value  # worst first
    md = audit_mod.as_markdown(results)
    assert "| repo |" in md
