"""Property-based tests (PBT) with the standard library only.

Kiro's spec-correctness workflow asks for properties: rules that must hold for
*all* inputs, not examples. These use seeded random generation so failures are
reproducible, and shrinking is manual (the failing value is printed by pytest).
"""

import random

from vigil.detectors import scan_files
from vigil.findings import Finding, Severity
from vigil.manifest import build_lock
from vigil.policy import Policy, evaluate
from vigil.proxy import sanitize_text
from vigil.score import score
from vigil.surface import SurfaceFile

HIDDEN = [0x200B, 0x200C, 0x200D, 0x202A, 0x202E, 0x2066, 0xE0041, 0xFE0F, 0xE0100]
VISIBLE = "abc XYZ 0123\n\t-_.:/"


def _visible(rng, n):
    return "".join(rng.choice(VISIBLE) for _ in range(n))


def test_sanitize_preserves_visible_text_and_is_idempotent():
    rng = random.Random(7)
    for _ in range(50):
        body = _visible(rng, rng.randint(0, 120))
        hidden = "".join(chr(rng.choice(HIDDEN)) for _ in range(rng.randint(0, 8)))
        cut = rng.randint(0, len(body))
        text = body[:cut] + hidden + body[cut:]

        clean, _removed, count = sanitize_text(text)

        assert count == len(hidden), (text, count)
        assert clean == body
        assert sanitize_text(clean)[2] == 0


def test_scanning_is_deterministic():
    rng = random.Random(11)
    for _ in range(25):
        text = _visible(rng, rng.randint(0, 300))
        surface = SurfaceFile("AGENTS.md", "agent_rules", text.encode())
        first = [f.to_dict() for f in scan_files([surface])]
        second = [f.to_dict() for f in scan_files([surface])]
        assert first == second


def test_manifest_root_is_order_independent_and_content_bound():
    rng = random.Random(13)
    for _ in range(20):
        files = [
            SurfaceFile(f"AGENTS-{i}.md", "agent_rules", _visible(rng, 40).encode())
            for i in range(4)
        ]
        forward = build_lock(files, scan_files(files))
        backward = build_lock(list(reversed(files)), scan_files(list(reversed(files))))
        assert forward["root"] == backward["root"]

        mutated = [
            SurfaceFile(f.path, f.kind, f.data + b"!") for f in files
        ]
        assert build_lock(mutated, scan_files(mutated))["root"] != forward["root"]


def test_score_is_bounded_and_never_increases_when_findings_are_added():
    base = Finding("AV-TST-001", "t", Severity.LOW, "AGENTS.md", "m")
    previous = score([base])[0]
    for i in range(30):
        extra = Finding(f"AV-TST-{i:03d}", "t", Severity.LOW, "AGENTS.md", "m")
        value = score([base, extra])[0]
        assert 0 <= value <= 100
        assert value <= previous
        previous = value


def test_allow_rules_always_exempt_their_rule():
    policy = Policy(deny=("exec.shell",), allow_rules=("AV-NET-001",), fail_on=Severity.INFO)
    for severity in Severity:
        finding = Finding("AV-NET-001", "t", severity, "AGENTS.md", "m")
        assert not evaluate([finding], policy).blocking
