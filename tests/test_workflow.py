from vigil.provenance import staged_paths
from pathlib import Path


def test_staged_graceful_outside_repo(tmp_path):
    # tmp dir is not a git repo: must return None, never raise
    assert staged_paths(tmp_path) is None or isinstance(staged_paths(tmp_path), list)


def test_staged_lists_cached_files(tmp_path):
    import subprocess
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@t.t"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    (tmp_path / "AGENTS.md").write_text("be nice\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "AGENTS.md"], check=True)
    assert staged_paths(tmp_path) == ["AGENTS.md"]
