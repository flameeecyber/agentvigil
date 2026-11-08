def test_cli_explain_and_init_and_monitor():
    import subprocess, sys, tempfile
    from pathlib import Path
    from conftest import EXAMPLES
    import shutil

    base = [sys.executable, "-m", "vigil.cli"]
    r = subprocess.run(base + ["explain", "AV-EXEC-001"], capture_output=True, text=True)
    assert r.returncode == 0 and "curl" in r.stdout or "pipe" in r.stdout
    r = subprocess.run(base + ["explain", "AV-NOPE-000"], capture_output=True, text=True)
    assert r.returncode != 0

    with tempfile.TemporaryDirectory() as tmp:
        shutil.copy(EXAMPLES / "clean-repo" / "AGENTS.md", Path(tmp) / "AGENTS.md")
        r = subprocess.run(base + ["init", tmp, "--preset", "balanced"], capture_output=True, text=True)
        assert r.returncode == 0
        assert (Path(tmp) / "vigil.lock").exists()
        assert (Path(tmp) / "vigil-policy.json").exists()
