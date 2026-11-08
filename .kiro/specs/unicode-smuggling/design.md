# Design: Unicode smuggling and steganography

## Overview

A single pass over the decoded UTF-8 text, classifying code points, decoding the
runs that carry data, then re-scanning the decoded payload with the deterministic
rule pack so hidden instructions inherit real capabilities.

## Pipeline

1. `SurfaceFile.text` decodes UTF-8 with replacement, so invalid bytes never raise.
2. Scan for tag characters (`U+E0020..U+E007F`), bidi controls
   (`U+202A..U+202E`, `U+2066..U+2069`), zero-width characters and variation
   selectors (`U+FE00..U+FE0F`, `U+E0100..U+E01EF`).
3. Decode tag runs to ASCII; decode variation selectors with three strategies
   (supplementary direct, nibble pairs, raw low-nibble bytes) and keep the first
   printable-ASCII result.
4. Re-scan the decoded payload through `patterns` and `entropy`; merge
   capabilities and record `metadata["inner_rules"]`.
5. Emit one finding per technique with the precise line/column of the first
   offending code point and `decoded` set to the payload.

## Decisions

- **Decode, don't just detect.** A finding that says "suspicious characters" is
  not reviewable; the decoded instruction is the evidence.
- **One BOM at index 0 is allowed.** A leading `U+FEFF` is a byte-order mark,
  not smuggling; later zero-width characters still fire.
- **Homoglyphs require an ASCII word context.** Cyrillic/Greek lookalikes inside
  an otherwise Latin word, to avoid flagging legitimate multilingual docs.
- **Pure functions only.** The detector takes a `SurfaceFile` and returns
  `Finding[]`; no file I/O, no network, no execution.

## Properties (PBT)

- Tag encode → decode is identity for printable ASCII payloads.
- `sanitize_text(decode(x))` never changes visible ASCII characters.
- Scanning the same bytes twice yields identical findings.
- A leading BOM produces no `AV-UNI-003`.

## Failure modes

- Mixed-script text (legitimate) can still trip `AV-UNI-006`; it is MEDIUM and can
  be exempted per path with a policy `allow_rules` entry.
- Variation-selector decoding is heuristic by nature; when no printable ASCII is
  recovered the finding still fires with an empty `decoded`.
