"""vigil — command line interface.

Exit codes are the contract:
  0  clean (or findings below the threshold)
  1  findings at/above --fail-on
  2  instruction surface is untrusted / changed since the lock
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from . import chain as chain_engine
from .detectors import patterns as pattern_pack
from .detectors import scan_files
from .detectors.multimodal import scan_png_chunks
from .diff import build_lock_at_ref, diff_surface
from .findings import SEVERITIES_BY_NAME, Severity, severity_at_least
from .manifest import (
    LOCK_NAME,
    build_lock,
    dumps,
    keygen,
    load_lock,
    sign_lock,
    verify_lock,
    write_lock,
)
from .report import as_diff_markdown, as_json, as_markdown, as_sarif, terminal
from .surface import discover, discover_assets

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_UNTRUSTED = 2


def _severity(value: str) -> Severity:
    try:
        return SEVERITIES_BY_NAME[value.lower()]
    except KeyError:
        raise argparse.ArgumentTypeError(
            f"unknown severity {value!r} (choose from {', '.join(SEVERITIES_BY_NAME)})"
        )


def cmd_scan(args: argparse.Namespace) -> int:
    import time as _time

    _t0 = _time.time()
    root = Path(args.path)
    if not root.exists():
        print(f"vigil: no such path: {root}", file=sys.stderr)
        return EXIT_UNTRUSTED

    files = discover(root)
    if getattr(args, "staged", False):
        from .provenance import staged_paths

        staged = staged_paths(root)
        if staged is not None:
            keep = set(staged)
            files = [f for f in files if f.path in keep]
            if not files:
                if not args.json and not args.sarif and not args.quiet:
                    print(
                        "vigil: no staged instruction-surface files — nothing to scan"
                    )
                return EXIT_CLEAN
    findings = scan_files(files, strict=getattr(args, "strict", False))
    # Co-located image assets reviewers skip but vision agents read.
    try:
        for asset in discover_assets(root):
            if asset.path.lower().endswith(".png"):
                findings.extend(scan_png_chunks(asset.data, asset.path))
    except OSError:
        pass
    # Kill-chain correlation: paths, not just alerts.
    if not getattr(args, "no_chains", False):
        findings.extend(chain_engine.correlate(files, findings))

    if args.llm:
        from .llm import adjudicate_differential

        findings.extend(adjudicate_differential(files, findings))

    # Policy gate overrides --fail-on when given.
    policy = None
    if getattr(args, "policy", None):
        from .policy import evaluate, load_policy

        try:
            policy = load_policy(Path(args.policy))
        except (OSError, ValueError) as exc:
            print(f"vigil: bad policy: {exc}", file=sys.stderr)
            return EXIT_UNTRUSTED
        verdict = evaluate(findings, policy)
        blocking = verdict.blocking
    else:
        blocking = any(severity_at_least(f.severity, args.fail_on) for f in findings)

    findings.sort(key=lambda f: f.sort_key())

    if getattr(args, "blame", False):
        from .provenance import annotate

        for finding, blame in zip(findings, annotate(root, findings)):
            if blame.known:
                finding.metadata["blame"] = blame.to_dict()

    if args.json:
        duration_ms = int((_time.time() - _t0) * 1000)
        sys.stdout.write(as_json(findings, files, duration_ms=duration_ms))
    elif args.sarif:
        sys.stdout.write(as_sarif(findings))
    elif getattr(args, "format", "text") == "markdown":
        sys.stdout.write(as_markdown(findings, files))
    elif not args.quiet:
        terminal(findings, files, verbose=args.verbose)

    if policy is not None and blocking:
        if (
            not args.json
            and not args.sarif
            and getattr(args, "format", "text") != "markdown"
        ):
            print(f"vigil: policy blocks — {verdict.reason}", file=sys.stderr)
        return EXIT_FINDINGS
    return EXIT_FINDINGS if blocking else EXIT_CLEAN


def cmd_manifest(args: argparse.Namespace) -> int:
    root = Path(args.path)
    files = discover(root)
    if not files:
        print("vigil: no instruction surface found — nothing to pin", file=sys.stderr)
        return EXIT_CLEAN
    findings = scan_files(files)
    lock = build_lock(files, findings, root)
    if getattr(args, "sign_keyless", False):
        try:
            import sigstore.oidc as _oidc  # type: ignore

            _ = _oidc
            print(
                "vigil: sigstore keyless requested but offline stub — use --sign-key for now",
                file=sys.stderr,
            )
            lock["signature"] = {
                "alg": "sigstore-stub",
                "key_id": "keyless",
                "value": "",
            }
        except ImportError:
            print(
                "vigil: sigstore not installed (`pip install sigstore` for keyless); "
                "falling back to unsigned",
                file=sys.stderr,
            )
            lock["signature"] = None
    elif args.sign_key:
        lock = sign_lock(lock, Path(args.sign_key))
    elif args.require_signature:
        print("vigil: --require-signature needs --sign-key", file=sys.stderr)
        return EXIT_UNTRUSTED
    else:
        lock["signature"] = None

    out = Path(args.output or (root / LOCK_NAME))
    write_lock(out, lock)
    status = "signed" if lock.get("signature") else "unsigned"
    print(f"vigil: pinned {lock['file_count']} file(s) → {out} ({status})")
    print(f"       merkle root {lock['root']}")
    if args.json:
        sys.stdout.write(dumps(lock))
    return EXIT_CLEAN


def cmd_verify(args: argparse.Namespace) -> int:
    root = Path(args.path)
    lock_path = Path(args.lock) if args.lock else root / LOCK_NAME
    if not lock_path.exists():
        print(
            f"vigil: no lockfile at {lock_path}; run `vigil manifest .`",
            file=sys.stderr,
        )
        return EXIT_UNTRUSTED
    lock = load_lock(lock_path)
    result = verify_lock(root, lock)

    if args.json:
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
    else:
        mark = "OK" if result["clean"] else "CHANGED"
        print(f"vigil: surface {mark} (root {result['expected_root'][:16]}…)")
        for key in ("added", "removed", "modified"):
            for path in result[key]:
                print(f"  {key:<9} {path}")

    if lock.get("signature") is None and args.require_signature:
        print("vigil: lockfile is unsigned", file=sys.stderr)
        return EXIT_UNTRUSTED
    import os as _os

    pub = _os.environ.get("AGENTVIGIL_PUBLIC_KEY", "")
    if pub and lock.get("signature"):
        from .manifest import verify_signature

        if not verify_signature(lock, pub):
            print(
                "vigil: signature DOES NOT verify against AGENTVIGIL_PUBLIC_KEY",
                file=sys.stderr,
            )
            return EXIT_UNTRUSTED
        if not args.json:
            print("vigil: signature verifies")
    return EXIT_CLEAN if result["clean"] and result["root_ok"] else EXIT_UNTRUSTED


def cmd_diff(args: argparse.Namespace) -> int:
    root = Path(args.path)
    base_ref = getattr(args, "base", None)
    if base_ref:
        try:
            lock = build_lock_at_ref(
                root, base_ref, strict=getattr(args, "strict", False)
            )
        except ValueError as exc:
            print(f"vigil: {exc}", file=sys.stderr)
            return EXIT_UNTRUSTED
    else:
        lock_path = Path(args.lock) if args.lock else root / LOCK_NAME
        if not lock_path.exists():
            print(
                f"vigil: no lockfile at {lock_path}; run `vigil manifest .` or pass `--base <git-ref>`",
                file=sys.stderr,
            )
            return EXIT_UNTRUSTED
        lock = load_lock(lock_path)
    fail_on = getattr(args, "fail_on", Severity.HIGH)
    result = diff_surface(
        root, lock, fail_on=fail_on, strict=getattr(args, "strict", False)
    )
    if lock.get("approvals"):
        from .approvals import is_approved

        kept = [
            c
            for c in result.added_capabilities
            if not any(is_approved(lock, d.path, c) for d in result.deltas)
        ]
        if len(kept) != len(result.added_capabilities):
            result.added_capabilities = tuple(kept)
            if not kept and not any(
                f
                for d in result.deltas
                for f in d.findings
                if f.severity.rank >= fail_on.rank
            ):
                result.blocking = False
                result.reason = (
                    "instruction surface changed; new capabilities are approved"
                )
    if getattr(args, "policy", None):
        from .policy import evaluate, load_policy

        try:
            policy = load_policy(Path(args.policy))
        except (OSError, ValueError) as exc:
            print(f"vigil: bad policy: {exc}", file=sys.stderr)
            return EXIT_UNTRUSTED
        flat = [f for d in result.deltas for f in d.findings]
        verdict = evaluate(flat, policy)
        result.blocking = verdict.blocking or result.blocking
        if verdict.blocking:
            result.reason = verdict.reason

    if args.json:
        sys.stdout.write(json.dumps(result.to_dict(), indent=2) + "\n")
    elif getattr(args, "format", "text") == "markdown":
        sys.stdout.write(
            as_diff_markdown(
                result.deltas, result.added_capabilities, result.blocking, result.reason
            )
        )
    else:
        if not result.changed:
            print("vigil: no change since the lock")
        else:
            print(f"vigil: {len(result.deltas)} file(s) changed since the lock")
            for delta in result.deltas:
                caps = ""
                if delta.added_capabilities:
                    caps = f"  +{', '.join(delta.added_capabilities)}"
                elif delta.removed_capabilities:
                    caps = f"  -{', '.join(delta.removed_capabilities)}"
                print(f"  {delta.status:<9} {delta.path}{caps}")
                for finding in delta.findings:
                    print(
                        f"            {finding.severity.value:<8} {finding.rule_id} "
                        f"{finding.path}:{finding.line} — {finding.title}"
                    )
                    if finding.decoded:
                        print(f"            decoded: {finding.decoded[:160]}")
        verdict_word = "BLOCKED" if result.blocking else "allowed"
        print(f"vigil: {verdict_word} — {result.reason}")

    return EXIT_UNTRUSTED if result.blocking else EXIT_CLEAN


def cmd_blame(args: argparse.Namespace) -> int:
    from .provenance import blame_line

    root = Path(args.path)
    target = args.target or ""
    if ":" in target:
        rel, _, lineno = target.rpartition(":")
        try:
            line = int(lineno)
        except ValueError:
            print(f"vigil: bad target {target!r} (want PATH[:LINE])", file=sys.stderr)
            return EXIT_UNTRUSTED
    else:
        rel, line = target, 1
    if not rel:
        print("usage: vigil blame AGENTS.md[:LINE]", file=sys.stderr)
        return EXIT_UNTRUSTED
    blame = blame_line(root, rel, line)
    if args.json:
        sys.stdout.write(json.dumps(blame.to_dict(), indent=2) + "\n")
    elif blame.known:
        print(f"vigil: {rel}:{line} ← {blame.commit} by {blame.author} ({blame.date})")
        if blame.summary:
            print(f"       {blame.summary}")
    else:
        print(f"vigil: {rel}:{line} — no git history (untracked or not a repo)")
    return EXIT_CLEAN


def cmd_fix(args: argparse.Namespace) -> int:
    """Safe auto-remediation preview (and opt-in apply).

    Only touches invisible smuggling characters and leaves every visible byte
    alone. Anything semantic (curl|sh, creds) is reported, never rewritten.
    """
    from .proxy import _STRIP_TABLE

    root = Path(args.path)
    files = discover(root)
    changed = 0
    for surface_file in files:
        try:
            text = surface_file.data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        clean = text.translate(_STRIP_TABLE)
        removed = len(text) - len(clean)
        if not removed:
            continue
        changed += 1
        print(f"  {surface_file.path}: would strip {removed} invisible char(s)")
        if args.apply:
            (root / surface_file.path).write_text(clean, encoding="utf-8")
    if not changed:
        print("vigil: nothing to strip — no invisible characters found")
    elif not args.apply:
        print("vigil: dry run — rerun with --apply to write the cleaned files")
    else:
        print(f"vigil: cleaned {changed} file(s); rerun `vigil scan .` to confirm")
    return EXIT_CLEAN


def cmd_rules(args: argparse.Namespace) -> int:
    if args.json:
        sys.stdout.write(json.dumps(pattern_pack.rules(), indent=2, default=str) + "\n")
        return EXIT_CLEAN
    print(f"{'rule':<14} {'severity':<9} {'technique':<10} title")
    for rule in pattern_pack.rules():
        print(
            f"{rule['id']:<14} {rule['severity'].value:<9} {rule['technique']:<10} {rule['title']}"
        )
    return EXIT_CLEAN


def cmd_keygen(args: argparse.Namespace) -> int:
    path = Path(args.key)
    if path.exists() and not args.force:
        print(f"vigil: {path} exists (use --force to overwrite)", file=sys.stderr)
        return EXIT_UNTRUSTED
    public_hex = keygen(path)
    print(f"vigil: wrote Ed25519 private key to {path} (mode 0600)")
    print(f"       public key (hex): {public_hex}")
    print("       store the public key in CI secrets as AGENTVIGIL_PUBLIC_KEY")
    return EXIT_CLEAN


def cmd_mcp(args: argparse.Namespace) -> int:
    from .proxy import run_proxy

    lock_path = Path(args.lock) if getattr(args, "lock", None) else None
    return run_proxy(
        args.server,
        lock_path=lock_path,
        block_poisoned=getattr(args, "block_poisoned", False),
    )


def cmd_serve(args: argparse.Namespace) -> int:
    from .serve import run as serve_run

    return serve_run(
        Path(args.path),
        host=args.host,
        port=args.port,
        theme=getattr(args, "theme", "plain"),
    )


def cmd_mcp_serve(args: argparse.Namespace) -> int:
    from .mcp_server import serve as serve_mcp

    return serve_mcp()


def cmd_policy_init(args: argparse.Namespace) -> int:
    import json as _json

    from .policy import PRESETS

    if args.preset not in PRESETS:
        print(
            f"vigil: unknown preset {args.preset!r} (choose {', '.join(PRESETS)})",
            file=sys.stderr,
        )
        return EXIT_UNTRUSTED
    out = Path(args.output)
    if out.exists() and not args.force:
        print(f"vigil: {out} exists (use --force to overwrite)", file=sys.stderr)
        return EXIT_UNTRUSTED
    out.write_text(_json.dumps(PRESETS[args.preset], indent=2) + "\n", encoding="utf-8")
    print(f"vigil: wrote {args.preset} policy → {out}")
    return EXIT_CLEAN


def cmd_explain(args: argparse.Namespace) -> int:
    from .detectors import STRICT_ONLY as _STRICT
    from .detectors import patterns as pack

    want = (args.rule or "").upper()
    catalog: list[dict] = list(pack.rules())
    catalog += [
        {
            "id": "AV-UNI-001",
            "severity": "critical",
            "technique": "M1.3",
            "title": "Hidden instruction in Unicode tag characters",
            "message": "Tag characters (U+E0020..U+E007F) encode invisible ASCII payloads.",
            "remediation": "Run `vigil fix . --apply` or delete the tag character run.",
        },
        {
            "id": "AV-UNI-002",
            "severity": "high",
            "technique": "M1.3",
            "title": "Bidirectional override character",
            "message": "Bidi control characters reorder rendered text vs raw model bytes.",
            "remediation": "Run `vigil fix . --apply` to strip bidi controls.",
        },
        {
            "id": "AV-UNI-005",
            "severity": "high",
            "technique": "M1.3",
            "title": "Variation-selector steganography run",
            "message": "Consecutive variation selectors (U+FE00..U+FE0F / U+E0100..U+E01EF) encode hidden bytes.",
            "remediation": "Run `vigil fix . --apply` and normalize text to NFC.",
        },
        {
            "id": "AV-OBF-002",
            "severity": "high",
            "technique": "M1.3",
            "title": "Encoded base64 payload decodes to executable content",
            "message": "Base64 blob decodes to shell/credential/network primitives.",
            "remediation": "Inline the readable text or remove the blob.",
        },
        {
            "id": "AV-OBF-003",
            "severity": "high",
            "technique": "M1.3",
            "title": "Encoded hex payload decodes to executable content",
            "message": "Hex blob decodes to shell/credential/network primitives.",
            "remediation": "Inline the readable text or remove the blob.",
        },
        {
            "id": "AV-IMG-001",
            "severity": "high",
            "technique": "M1.4",
            "title": "Active content in SVG",
        },
        {
            "id": "AV-IMG-004",
            "severity": "high",
            "technique": "M1.4",
            "title": "Instruction delegates behaviour to a remote image",
        },
        {
            "id": "AV-IMG-010",
            "severity": "medium",
            "technique": "M1.4",
            "title": "Instruction-like text inside PNG metadata",
        },
        {
            "id": "AV-MCP-001",
            "severity": "high",
            "technique": "D3.1",
            "title": "Unpinned MCP package install",
        },
        {
            "id": "AV-MCP-007",
            "severity": "high",
            "technique": "D3.1",
            "title": "Inline code interpreter or tunnel in MCP command",
            "message": "MCP server uses inline execution (`python -c`, `node -e`) or reverse tunnel.",
            "remediation": "Use a version-pinned package entrypoint instead of inline scripts.",
        },
        {
            "id": "AV-MCP-008",
            "severity": "critical",
            "technique": "D3.1",
            "title": "Cross-tool shadowing or poisoned MCP descriptor",
            "message": "MCP config/tool description attempts to hijack other tools or exfiltrate parameters.",
            "remediation": "Remove the poisoned server/tool and wrap untrusted servers with `vigil mcp --block-poisoned`.",
        },
        {
            "id": "AV-REF-001",
            "severity": "high",
            "technique": "D2.2",
            "title": "Context reference escapes repository root or targets secrets",
            "message": "A `#[[file:...]]` or `@path` directive traverses outside the repo or targets credentials.",
            "remediation": "Keep all context references inside reviewed repository directories.",
        },
        {
            "id": "AV-REF-002",
            "severity": "high",
            "technique": "D3.1",
            "title": "Mutable external skill or branch-pinned instruction import",
            "message": "Instruction imports an unpinned skill package or branch-mutable raw URL.",
            "remediation": "Vendor the skill file and pin it in `vigil.lock`, or pin to an immutable commit SHA.",
        },
        {
            "id": "AV-REF-003",
            "severity": "medium",
            "technique": "M2.2",
            "title": "Shadow instruction surface via context include",
            "message": "A `#[[file:...]]` directive pulls a non-surface file into agent steering context.",
            "remediation": "Move shared instructions into `.kiro/steering/` or review the target file.",
        },
        {
            "id": "AV-CHAIN-001",
            "severity": "critical",
            "technique": "P3.1",
            "title": "Kill chain: remote instruction + execution",
        },
        {
            "id": "AV-CHAIN-002",
            "severity": "critical",
            "technique": "P3.1",
            "title": "Kill chain: credential access + exfiltration sink",
        },
        {
            "id": "AV-CHAIN-003",
            "severity": "high",
            "technique": "P3.1",
            "title": "Kill chain: concealment + persistence or approval bypass",
        },
        {
            "id": "AV-CHAIN-004",
            "severity": "critical",
            "technique": "P3.1",
            "title": "Kill chain: unpinned MCP server receives cloud credentials",
        },
    ]
    match = next((r for r in catalog if str(r.get("id", "")).upper() == want), None)
    if not match:
        print(f"vigil: unknown rule {args.rule!r} — try `vigil rules`", file=sys.stderr)
        return EXIT_UNTRUSTED
    tier = "strict-only" if match["id"] in _STRICT else "default"
    print(f"{match['id']} [{tier}] {match.get('title', '')}")
    print(f"  technique: {match.get('technique', '—')}")
    if match.get("message"):
        print(f"  what: {match['message']}")
    if match.get("remediation"):
        print(f"  fix: {match['remediation']}")
    return EXIT_CLEAN


def cmd_init(args: argparse.Namespace) -> int:
    """One-command onboarding: lock + policy + hook + workflow stub."""
    import json as _json

    from .approvals import approve as _approve
    from .policy import PRESETS

    root = Path(args.path).resolve()
    files = discover(root)
    if not files:
        print("vigil: no instruction surface found — nothing to init", file=sys.stderr)
        return EXIT_UNTRUSTED
    lock_path = root / LOCK_NAME
    if not lock_path.exists() or args.force:
        findings = scan_files(files, strict=False)
        write_lock(lock_path, build_lock(files, findings, root))
        print(f"vigil: wrote {lock_path.name} ({len(files)} files)")
    policy_path = root / "vigil-policy.json"
    if not policy_path.exists() or args.force:
        policy_path.write_text(_json.dumps(PRESETS[args.preset], indent=2) + "\n")
        print(f"vigil: wrote {policy_path.name} ({args.preset})")
    hook_src = Path(__file__).resolve().parents[1] / ".kiro" / "hooks" / "pre-commit.sh"
    if hook_src.exists():
        dest = root / ".git" / "hooks" / "pre-commit"
        if dest.parent.exists() and (args.force or not dest.exists()):
            try:
                import shutil

                shutil.copy(hook_src, dest)
                dest.chmod(0o755)
                print("vigil: installed .git/hooks/pre-commit")
            except OSError as exc:
                print(f"vigil: hook install skipped: {exc}", file=sys.stderr)
    print("vigil: next: vigil scan . · vigil diff · vigil serve --port 8000")
    return EXIT_CLEAN


def cmd_dashboard(args: argparse.Namespace) -> int:
    from . import dashboard as dash_mod

    Path(args.output).write_text(
        dash_mod.build(Path(args.path), max_repos=args.max_repos), encoding="utf-8"
    )
    print(f"vigil: wrote dashboard → {args.output}")
    return EXIT_CLEAN


def cmd_sbom(args: argparse.Namespace) -> int:
    from . import sbom as sbom_mod

    sys.stdout.write(
        sbom_mod.dumps(Path(args.path), strict=getattr(args, "strict", False))
    )
    return EXIT_CLEAN


def cmd_timeline(args: argparse.Namespace) -> int:
    import json as _json

    from . import timeline as tl_mod

    points = tl_mod.timeline(Path(args.path), max_commits=args.max)
    if not points:
        print("vigil: no git history — timeline needs a git repo")
        return EXIT_CLEAN
    if getattr(args, "json", False):
        sys.stdout.write(_json.dumps([p.__dict__ for p in points], indent=2) + "\n")
    else:
        for p in points:
            print(
                f"  {p.commit} {p.date}  {p.trust:>3}/100 {p.grade}  "
                f"{p.findings} findings in {p.files} files"
            )
    return EXIT_CLEAN


def cmd_badge(args: argparse.Namespace) -> int:
    root = Path(args.path)
    files = discover(root)
    findings = scan_files(files, strict=False)
    from .score import score as _score

    value, grade, _ = _score(findings)
    url = args.url.rstrip("/") if args.url else ""
    img = f"{url}/badge.svg" if url else "badge.svg"
    sys.stdout.write(f"[![agentvigil {value}/100 {grade}]({img})]({url or '.'})\n")
    return EXIT_CLEAN


def cmd_bench_new(args: argparse.Namespace) -> int:
    base = Path("bench/payloads") / args.technique / args.slug
    base.mkdir(parents=True, exist_ok=True)
    (base / "file.md").write_text(args.body + "\n", encoding="utf-8")
    (base / "expected.json").write_text(
        __import__("json").dumps({"must_fire": args.must_fire}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"vigil: scaffolded {base} — edit file.md, run `python -m bench.run`")
    return EXIT_CLEAN


def cmd_evidence(args: argparse.Namespace) -> int:
    import json as _json

    from . import sbom as sbom_mod
    from .manifest import load_lock
    from .provenance import annotate

    root = Path(args.path)
    doc = sbom_mod.build(root)
    lock_path = root / LOCK_NAME
    if lock_path.exists():
        lock = load_lock(lock_path)
        doc["lock"] = {
            "root": lock.get("root"),
            "files": len(lock.get("files", [])),
            "approvals": lock.get("approvals", []),
            "signature": lock.get("signature"),
        }
    files = discover(root)
    findings = scan_files(files, strict=False)
    doc["blame"] = [b.to_dict() for b in annotate(root, findings[:20])]
    sys.stdout.write(_json.dumps(doc, indent=2) + "\n")
    return EXIT_CLEAN


def cmd_monitor(args: argparse.Namespace) -> int:
    """One-shot drift check for cron: compare working tree against the lock."""
    import json as _json

    root = Path(args.path)
    lock_path = Path(args.lock) if args.lock else root / LOCK_NAME
    if not lock_path.exists():
        print(
            f"vigil: no lockfile at {lock_path}; run `vigil manifest .`",
            file=sys.stderr,
        )
        return EXIT_UNTRUSTED
    lock = load_lock(lock_path)
    result = diff_surface(
        root, lock, fail_on=Severity.HIGH, strict=getattr(args, "strict", False)
    )
    payload = {
        "repo": str(root),
        "changed": result.changed,
        "blocking": result.blocking,
        "reason": result.reason,
        "added_capabilities": list(result.added_capabilities),
        "files": [d.to_dict() for d in result.deltas],
    }
    if getattr(args, "json", False):
        sys.stdout.write(_json.dumps(payload, indent=2) + "\n")
    else:
        state = "DRIFT" if result.changed else "OK"
        print(f"vigil monitor: {state} — {result.reason}")
    if getattr(args, "webhook", None) and result.blocking:
        try:
            import urllib.request as _url

            req = _url.Request(
                getattr(args, "webhook"),
                data=_json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            with _url.urlopen(req, timeout=10):
                pass
            print("vigil: webhook delivered")
        except Exception as exc:
            print(f"vigil: webhook failed: {exc}", file=sys.stderr)
    return EXIT_UNTRUSTED if result.blocking else EXIT_CLEAN


def cmd_approve(args: argparse.Namespace) -> int:
    from .approvals import approve

    if not args.by or not args.reason:
        print(
            "vigil: --by and --reason are required (who accepted this and why)",
            file=sys.stderr,
        )
        return EXIT_UNTRUSTED
    result = approve(
        Path(args.path),
        by=args.by,
        reason=args.reason,
        lock_path=Path(args.lock) if args.lock else None,
    )
    print(
        f"vigil: approved {result['approved']} capabilitie(s) by {result['by']} → {result['lock']}"
    )
    print("       rerun `vigil diff` — approved capabilities no longer block")
    return EXIT_CLEAN


def cmd_graph(args: argparse.Namespace) -> int:
    from . import graph as graph_mod

    root = Path(args.path)
    files = discover(root)
    findings = scan_files(files)
    if args.format == "html":
        out = graph_mod.to_html(files, findings)
    elif args.format == "svg":
        out = graph_mod.to_svg(files, findings)
    else:
        out = graph_mod.to_dot(files, findings)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"vigil: wrote graph ({args.format}) → {args.output}")
    else:
        sys.stdout.write(out)
    return EXIT_CLEAN


def cmd_canary(args: argparse.Namespace) -> int:
    from . import canary as canary_mod

    root = Path(args.path)
    lock_path = Path(args.lock) if getattr(args, "lock", None) else root / LOCK_NAME
    if getattr(args, "check", None):
        target = Path(args.check)
        if not target.exists():
            print(f"vigil: no such file: {target}", file=sys.stderr)
            return EXIT_UNTRUSTED
        lock = load_lock(lock_path) if lock_path.exists() else None
        text = target.read_text(encoding="utf-8", errors="replace")
        hits = canary_mod.check_text(text, lock=lock)
        if getattr(args, "json", False):
            sys.stdout.write(json.dumps([h.to_dict() for h in hits], indent=2) + "\n")
        elif hits:
            for h in hits:
                print(
                    f"vigil: CANARY TRIPPED [{h.encoding}] id={h.canary_id} at {target}:{h.line}"
                )
                print(f"       snippet: {h.snippet}")
        else:
            print(f"vigil: no canary tokens detected in {target}")
        return EXIT_FINDINGS if hits else EXIT_CLEAN

    canary = canary_mod.register_canary(root, label=args.label, lock_path=lock_path)
    if getattr(args, "json", False):
        sys.stdout.write(
            json.dumps({**canary.to_dict(), "token": canary.token}, indent=2) + "\n"
        )
    else:
        print(
            f"vigil: registered canary {canary.canary_id} ({canary.label}) → {lock_path}"
        )
        print(f"       token: {canary.token}")
        print(f"       embed: <!-- vigil-canary: {canary.token} -->")
        print("       next:  vigil canary . --check <agent-transcript.log>")
    return EXIT_CLEAN


def cmd_audit(args: argparse.Namespace) -> int:
    from . import audit as audit_mod

    results = audit_mod.audit(Path(args.path), max_repos=args.max_repos)
    if not results:
        print("vigil: no repos with an instruction surface found")
        return EXIT_CLEAN
    if args.format == "json":
        sys.stdout.write(audit_mod.as_json(results))
    elif args.format == "markdown":
        sys.stdout.write(audit_mod.as_markdown(results))
    else:
        for r in results:
            print(
                f"  {r.value:>3}/100 {r.grade}  {r.name:<24} {len(r.findings)} finding(s)"
            )
    return EXIT_CLEAN


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigil",
        description="Supply-chain security for the instructions your AI agent obeys.",
    )
    parser.add_argument(
        "--version", action="version", version=f"agentvigil {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="audit the instruction surface of a repository")
    scan.add_argument(
        "path", nargs="?", default=".", help="repository root (default: .)"
    )
    scan.add_argument("--json", action="store_true", help="machine-readable findings")
    scan.add_argument(
        "--sarif", action="store_true", help="SARIF 2.1.0 for GitHub code scanning"
    )
    scan.add_argument(
        "--fail-on",
        type=_severity,
        default=Severity.HIGH,
        metavar="LEVEL",
        help="critical|high|medium|low|info (default: high)",
    )
    scan.add_argument(
        "--llm",
        action="store_true",
        help="add semantic adjudication (needs a provider)",
    )
    scan.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show remediation and technique ids",
    )
    scan.add_argument("-q", "--quiet", action="store_true", help="no terminal output")
    scan.add_argument(
        "--policy", default=None, help="org policy JSON (deny capabilities per path)"
    )
    scan.add_argument(
        "--blame", action="store_true", help="attach git blame to each finding"
    )
    scan.add_argument("--format", choices=["text", "markdown"], default="text")
    scan.add_argument(
        "--no-chains", action="store_true", help="disable kill-chain correlation"
    )
    scan.add_argument(
        "--strict", action="store_true", help="include noisy LOW/INFO rules"
    )
    scan.add_argument(
        "--staged", action="store_true", help="scan only git-staged surface files"
    )
    scan.set_defaults(func=cmd_scan)

    man = sub.add_parser("manifest", help="pin the instruction surface to vigil.lock")
    man.add_argument(
        "path", nargs="?", default=".", help="repository root (default: .)"
    )
    man.add_argument(
        "-o", "--output", help="lockfile path (default: <root>/vigil.lock)"
    )
    man.add_argument(
        "--sign-key", help="Ed25519 private key (PEM) used to sign the lock"
    )
    man.add_argument(
        "--sign-keyless",
        action="store_true",
        help="sigstore keyless (CI; stub if offline)",
    )
    man.add_argument(
        "--require-signature",
        action="store_true",
        help="fail if no signing key is given",
    )
    man.add_argument(
        "--json", action="store_true", help="also print the lock to stdout"
    )
    man.set_defaults(func=cmd_manifest)

    verify = sub.add_parser("verify", help="check the surface against vigil.lock")
    verify.add_argument(
        "path", nargs="?", default=".", help="repository root (default: .)"
    )
    verify.add_argument(
        "--lock", default=None, help="lockfile path (default: <root>/vigil.lock)"
    )
    verify.add_argument("--require-signature", action="store_true")
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(func=cmd_verify)

    diff = sub.add_parser(
        "diff", help="what changed since the lock, and what it lets the agent do"
    )
    diff.add_argument(
        "path", nargs="?", default=".", help="repository root (default: .)"
    )
    diff.add_argument(
        "--lock", default=None, help="lockfile path (default: <root>/vigil.lock)"
    )
    diff.add_argument(
        "--base",
        default=None,
        help="compare against a git ref (e.g. main, HEAD~1) without vigil.lock",
    )
    diff.add_argument(
        "--fail-on", type=_severity, default=Severity.HIGH, metavar="LEVEL"
    )
    diff.add_argument("--json", action="store_true")
    diff.add_argument(
        "--format",
        choices=["text", "markdown"],
        default="text",
        help="markdown prints a PR-comment body",
    )
    diff.add_argument(
        "--policy", default=None, help="org policy JSON enforced on the delta"
    )
    diff.add_argument(
        "--strict", action="store_true", help="include noisy LOW/INFO rules"
    )
    diff.set_defaults(func=cmd_diff)

    rules = sub.add_parser("rules", help="list the pattern rule pack")
    rules.add_argument("--json", action="store_true")
    rules.set_defaults(func=cmd_rules)

    key = sub.add_parser("keygen", help="create an Ed25519 key for signing lockfiles")
    key.add_argument("--key", default="vigil-signing-key.pem")
    key.add_argument("--force", action="store_true")
    key.set_defaults(func=cmd_keygen)

    mcp = sub.add_parser("mcp", help="run an MCP server behind the sanitizing proxy")
    mcp.add_argument(
        "--lock",
        default=None,
        help="pin and verify tool descriptor hashes in vigil.lock",
    )
    mcp.add_argument(
        "--block-poisoned",
        action="store_true",
        help="replace poisoned tool descriptions before forwarding to the client",
    )
    mcp.add_argument(
        "server",
        nargs=argparse.REMAINDER,
        help="server command after `--`, e.g. vigil mcp -- npx -y pkg",
    )
    mcp.set_defaults(func=cmd_mcp)

    serve = sub.add_parser(
        "serve", help="read-only HTML/JSON demo server (no code execution)"
    )
    serve.add_argument(
        "path", nargs="?", default=".", help="repository root (default: .)"
    )
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument(
        "--theme",
        choices=["plain", "kiroween"],
        default="plain",
        help="kiroween renders the haunted Costume-Contest report",
    )
    serve.set_defaults(func=cmd_serve)

    mcp_serve = sub.add_parser(
        "mcp-serve", help="run agentvigil as a read-only MCP server on stdio"
    )
    mcp_serve.set_defaults(func=cmd_mcp_serve)

    approve = sub.add_parser(
        "approve", help="accept current capabilities with reviewer+reason"
    )
    approve.add_argument(
        "path", nargs="?", default=".", help="repository root (default: .)"
    )
    approve.add_argument(
        "--lock", default=None, help="lockfile path (default: <root>/vigil.lock)"
    )
    approve.add_argument("--by", default="", help="reviewer name (required)")
    approve.add_argument("--reason", default="", help="why this is safe (required)")
    approve.set_defaults(func=cmd_approve)

    graph = sub.add_parser("graph", help="export attack paths as DOT, SVG, or HTML")
    graph.add_argument(
        "path", nargs="?", default=".", help="repository root (default: .)"
    )
    graph.add_argument("--format", choices=["dot", "svg", "html"], default="dot")
    graph.add_argument("-o", "--output", default=None)
    graph.set_defaults(func=cmd_graph)

    canary = sub.add_parser(
        "canary", help="mint repo-scoped canary tokens or check logs for exfiltration"
    )
    canary.add_argument(
        "path", nargs="?", default=".", help="repository root (default: .)"
    )
    canary.add_argument(
        "--lock", default=None, help="lockfile path (default: <root>/vigil.lock)"
    )
    canary.add_argument(
        "--label", default="default", help="canary label (default: default)"
    )
    canary.add_argument(
        "--check",
        default=None,
        metavar="FILE",
        help="scan an agent transcript/log for raw, base64, or hex canary leaks",
    )
    canary.add_argument("--json", action="store_true")
    canary.set_defaults(func=cmd_canary)

    audit = sub.add_parser("audit", help="trust rollup across repos in a directory")
    audit.add_argument(
        "path", nargs="?", default=".", help="directory of repos (default: .)"
    )
    audit.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    audit.add_argument("--max-repos", type=int, default=50)
    audit.set_defaults(func=cmd_audit)

    policy_init = sub.add_parser("policy-init", help="write a starter org policy file")
    policy_init.add_argument(
        "--preset", choices=["strict", "balanced", "permissive"], default="balanced"
    )
    policy_init.add_argument("-o", "--output", default="vigil-policy.json")
    policy_init.add_argument("--force", action="store_true")
    policy_init.set_defaults(func=cmd_policy_init)

    monitor = sub.add_parser(
        "monitor", help="one-shot drift check for cron (exits 2 on drift)"
    )
    monitor.add_argument(
        "path", nargs="?", default=".", help="repository root (default: .)"
    )
    monitor.add_argument("--lock", default=None)
    monitor.add_argument("--strict", action="store_true")
    monitor.add_argument("--json", action="store_true")
    monitor.add_argument(
        "--webhook", default=None, help="POST drift JSON here (SOC alerting)"
    )
    monitor.set_defaults(func=cmd_monitor)

    badge = sub.add_parser("badge", help="README badge markdown for this repo")
    badge.add_argument("path", nargs="?", default=".")
    badge.add_argument("--url", default="", help="deployed serve URL prefix")
    badge.set_defaults(func=cmd_badge)

    bench_new = sub.add_parser("bench-new", help="scaffold a benchmark payload")
    bench_new.add_argument("technique", help="e.g. D2.1")
    bench_new.add_argument("slug", help="e.g. curl-pipe")
    bench_new.add_argument("--body", default="suspicious instruction here")
    bench_new.add_argument("--must-fire", nargs="*", default=[])
    bench_new.set_defaults(func=cmd_bench_new)

    evidence = sub.add_parser(
        "evidence", help="GRC bundle: sbom + lock + approvals + blame"
    )
    evidence.add_argument("path", nargs="?", default=".")
    evidence.set_defaults(func=cmd_evidence)

    dashboard = sub.add_parser("dashboard", help="single-file HTML org report")
    dashboard.add_argument("path", nargs="?", default=".")
    dashboard.add_argument("-o", "--output", default="dashboard.html")
    dashboard.add_argument("--max-repos", type=int, default=50)
    dashboard.set_defaults(func=cmd_dashboard)

    sbom = sub.add_parser(
        "sbom", help="instruction-surface SBOM (CycloneDX-style JSON)"
    )
    sbom.add_argument("path", nargs="?", default=".")
    sbom.add_argument("--strict", action="store_true")
    sbom.set_defaults(func=cmd_sbom)

    timeline = sub.add_parser("timeline", help="trust over recent git history")
    timeline.add_argument("path", nargs="?", default=".")
    timeline.add_argument("--max", type=int, default=20)
    timeline.add_argument("--json", action="store_true")
    timeline.set_defaults(func=cmd_timeline)

    explain = sub.add_parser("explain", help="what a rule means and how to fix it")
    explain.add_argument("rule", help="e.g. AV-EXEC-001")
    explain.set_defaults(func=cmd_explain)

    init = sub.add_parser("init", help="one-command onboarding: lock + policy + hook")
    init.add_argument(
        "path", nargs="?", default=".", help="repository root (default: .)"
    )
    init.add_argument(
        "--preset", choices=["strict", "balanced", "permissive"], default="balanced"
    )
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=cmd_init)

    blame = sub.add_parser(
        "blame", help="who introduced this instruction (git history)"
    )
    blame.add_argument(
        "target", nargs="?", default="", help="PATH[:LINE] e.g. AGENTS.md:14"
    )
    blame.add_argument(
        "path", nargs="?", default=".", help="repository root (default: .)"
    )
    blame.add_argument("--json", action="store_true")
    blame.set_defaults(func=cmd_blame)

    fix = sub.add_parser(
        "fix", help="strip invisible smuggling chars (dry run by default)"
    )
    fix.add_argument(
        "path", nargs="?", default=".", help="repository root (default: .)"
    )
    fix.add_argument("--apply", action="store_true", help="write the cleaned files")
    fix.set_defaults(func=cmd_fix)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "server", None) and args.server and args.server[0] == "--":
        args.server = args.server[1:]
    try:
        return int(args.func(args) or 0)
    except BrokenPipeError:
        return EXIT_CLEAN
    except RuntimeError as exc:
        print(f"vigil: {exc}", file=sys.stderr)
        return EXIT_UNTRUSTED


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
