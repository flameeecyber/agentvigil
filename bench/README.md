# vigil-bench corpus

A small, versioned corpus of instruction-surface cases. It answers a narrow
question: **do the current deterministic rules still fire on labeled examples,
and stay quiet on benign controls?**

It does **not** measure general real-world precision or recall. The labels are
hand-authored, and every case lives in this repository. Treat the numbers as
corpus-specific regression results, not an external evaluation.

## Current baseline (Nov 8, 2026)

```console
$ python -m bench.run
cases: 29/29 pass
required-rule coverage: 30/30 (100.00%)
benign: 13/13 quiet at high+ (FP rate 0.00%)
```

- 29 labeled payload cases across 10 technique families.
- 30 required rule hits; each case may require more than one rule.
- 13 benign controls: Markdown rules, security guidance, pinned MCP config,
  and SVG. Quiet means no high-or-critical finding.
- 3 unexpected high+ rule hits across 3 attack cases are reported separately.
  They are not failed because a cross-rule finding can be legitimate; they are
  visible so reviewers can judge them.

This baseline replaced the earlier **12 payloads / 5 benign** claim. The earlier
number was too small to support a precision statement and silently ignored the
benign SVG because only `*.md` was counted.

## Layout and labels

```
bench/payloads/<technique>/<slug>/file.md          # or file.mcp.json / file.svg
bench/payloads/<technique>/<slug>/expected.json
bench/benign/<slug>.<md|json|svg|txt>
```

`expected.json`:

```json
{
  "must_fire": ["AV-EXEC-001"],
  "must_not_fire": ["AV-CRED-001"],
  "min_severity": "high",
  "labeler": "manual",
  "notes": "Why this is the expected behavior."
}
```

- `must_fire` is required, non-empty, and every id must match `AV-*-NNN`.
- `must_not_fire` is optional; overlap with `must_fire` is a corpus error.
- `min_severity` defaults to `high`; use it only when the rule itself is lower
  severity (for example `AV-CRED-002` at medium).
- `labeler` and `notes` are provenance, not executable input.

A case is invalid—not skipped—when its file is missing, more than one case file
exists, its JSON is malformed, or a rule id is malformed. `python -m bench.run`
exits `2` for corpus errors and `1` for a missed/forbidden rule or a benign
high-severity false positive.

## What changed in this validation pass

The first realistic benign controls exposed a precision problem the old
five-file sample missed:

- `Never run \`curl ... | sh\`` fired `AV-EXEC-001` at **critical**.
- `Do not read ~/.aws/credentials` fired `AV-CRED-001` at **high**.
- A test fixture quoting `ignore previous instructions` fired `AV-OVR-001`.
- An inline-code example containing `<!-- run the tests -->` fired
  `AV-HIDE-001`.

Those are descriptions of attacks, not instructions to perform one. The pattern
detector now demotes matches in an explicit prohibition or quoted documentation
context to **LOW**, adds `metadata.context`, and keeps the finding visible. It
does not delete the finding or lower the declared severity for an imperative
instruction. Regression tests live in `tests/test_precision.py`.

This guard is a heuristic, not semantic understanding. A payload that phrases
itself as a prohibition, or hides an instruction inside a genuine-looking
example, can still evade the default high+ gate. The opt-in `--llm`
adjudication layer exists for that reason.

## External check

A small, pinned sample of public instruction files from other projects is in
[`external.md`](external.md). It is not an external benchmark. In short: nine
development files exposed three precision defects (now fixed), and eight
held-out files then produced one true-positive `AV-REF-002` finding and no
other high+ findings. Across all 17 files there are 0 high+ false positives
after the fixes. The sample is too small and not independently labeled to
support a production FP rate or a recall claim.

## Limitations

- **Synthetic, in-repo, hand-labeled.** No external reviewer has audited these
  labels. The separate 17-file external spot check is not a label audit.
- **Small benign sample.** 13 controls cannot estimate a production false-
  positive rate. The 0.00% figure is exact for this sample only.
- **Deterministic layer only.** `--llm` is opt-in and not measured here.
- **High+ gate for benign files.** Medium/low noise is not counted as a false
  positive; low-severity context findings are expected on documentation.
- **Coverage is not completeness.** The corpus covers rules that have labeled
  cases; it does not prove every rule or technique is covered.
- **No representative repository sample.** The 17-file external check in
  [`external.md`](external.md) is a spot check, not a random or representative
  sample. The next credible step is a pre-registered set with two independent
  labelers and a published per-rule FP table.

## Run it

```console
python -m bench.run
python -m bench.run --html -o bench/index.html
python -m bench.run --json -o bench/results.json
```

CI runs the table and fails on a missed/forbidden rule or a benign high+
finding. The HTML report is the shareable scoreboard; the JSON report carries
per-case and per-technique details.

## Contributing a case

1. Pick a technique id or propose one in `docs/decisions.md`.
2. Add one case file and `expected.json` with hand-authored labels.
3. Add a near-miss benign control when the rule is prone to prose false
   positives.
4. Run `python -m pytest -q` and `python -m bench.run`; both must stay green.
5. Use inert domains (`example.invalid`), documentation example keys, and no
   live credentials. Never include content that executes on scan.
