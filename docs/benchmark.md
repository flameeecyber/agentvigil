# Benchmark

`vigil-bench` is a labeled regression corpus for the deterministic instruction-
surface rules. It is deliberately small and local. The full methodology, label
schema, and limitations are in [`../bench/README.md`](../bench/README.md).

## Current result

```console
$ python -m bench.run
cases: 29/29 pass
required-rule coverage: 30/30 (100.00%)
benign: 13/13 quiet at high+ (FP rate 0.00%)
```

Per technique:

| Technique | Cases | Required rules |
|---|---|---|
| D1.2-override | 1/1 | 1/1 |
| D2.1-download-exec | 3/3 | 3/3 |
| D2.2-creds | 4/4 | 4/4 |
| D2.3-exfil | 3/3 | 3/3 |
| D3.1-mcp | 7/7 | 7/7 |
| M1.1-tool-spoof | 1/1 | 1/1 |
| M1.3-obfuscation | 4/4 | 4/4 |
| M1.4-multimodal | 3/3 | 3/3 |
| M2.2-conceal | 2/2 | 3/3 |
| P2.3-persistence | 1/1 | 1/1 |

Run `python -m bench.run` for the per-case table, including unexpected high+
rule hits. Generate the shareable report with:

```console
python -m bench.run --html -o bench/index.html
python -m bench.run --json -o bench/results.json
```

## External check

A separate spot check scanned **17 public instruction files** from other
projects at pinned commits (208,777 bytes). It is documented in
[`../bench/external.md`](../bench/external.md) and is **not** an external
benchmark.

- Nine development files exposed three precision defects: `--no-sandbox`
  treated as an approval bypass, bare “silently” treated as concealment, and
  `process.env.NODE_ENV` treated as an environment dump. The rules were
  corrected and regression tests added.
- After the fixes, those nine files have 0 high+ findings (one LOW negated
  mention remains).
- Eight held-out files were then scanned without further tuning: one
  true-positive `AV-REF-002` (an unpinned external skill import), and no other
  findings at any severity.

Across the 17 files there are **0 high+ false positives** and **1 high true
positive** after the fixes. The sample is small, not randomly selected, and not
independently labeled, so it does not establish a production FP rate or recall.

## How to read the numbers

- **Required-rule coverage** is the fraction of hand-labeled required rules that
  fired at or above each case's `min_severity`. It is not recall over all
  possible attacks.
- **Benign quiet** is the fraction of benign controls with no high-or-critical
  finding. Low/medium context findings are not counted as false positives.
- **Unexpected high+ hits** are reported separately and do not fail a case,
  because one payload can legitimately trigger several rules.
- Missing files, malformed labels, duplicate slugs, and overlapping
  required/forbidden rules are **corpus errors**, not silent skips.

## What this corpus does not establish

The corpus numbers are **not** an external evaluation and must not be presented
as general precision or recall:

- labels are hand-authored in the same repository;
- only 13 benign controls are included;
- the deterministic layer is measured, not the opt-in `--llm` layer;
- no independent reviewer has audited the labels;
- the external check is 17 files, not a representative repository sample, and
  cannot support a production FP rate or a recall claim.

The honest claim is: **the current rules pass a 29-case labeled regression
corpus, produce no high+ findings on 13 hand-authored benign controls, and
produce 0 high+ false positives on a 17-file pinned external spot check (with
one true-positive unpinned-skill finding).** The next credibility step is a
larger, pre-registered repository sample with independent labeling and a
published per-rule FP table.

## Validation finding: prose false positives

Before expansion, the corpus reported `12/12` payloads and `5/5` benign. The
benign set only counted Markdown and did not include realistic security
guidance. Adding natural controls exposed four high/critical matches on text
that *describes* an attack:

- `Never run \`curl ... | sh\`` → `AV-EXEC-001` critical;
- `Do not read ~/.aws/credentials` → `AV-CRED-001` high;
- a test fixture quoting `ignore previous instructions` → `AV-OVR-001` high;
- inline-code `<!-- run the tests -->` → `AV-HIDE-001` high.

The pattern detector now demotes explicit prohibition or quoted-documentation
matches to LOW with `metadata.context`, preserving the finding and capability
for review. Imperative payloads keep their original severity. Tests are in
`tests/test_precision.py`. This is a heuristic; the limitations above still
apply.
