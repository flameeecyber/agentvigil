# Spec: Unicode Smuggling & Steganography Detector (`AV-UNI-001..006`)

## Problem Statement
Instruction files (`AGENTS.md`, `SKILL.md`, `.cursorrules`) are rendered as rich Markdown or UTF-8 text where tag characters (`U+E0000..U+E007F`), bidi controls, zero-width characters, and variation selectors (`U+FE00..U+FE0F`, `U+E0100..U+E01EF`) are invisible to human code reviewers while being tokenized and obeyed by LLMs.

## Acceptance Criteria
1. **WHEN** a surface file contains Unicode tag characters (`U+E0020..U+E007F`), **THE SYSTEM SHALL** emit `AV-UNI-001` (`critical`) with the exact line/column span and the decoded ASCII payload in `finding.decoded`.
2. **WHEN** a decoded tag or variation-selector payload contains executable or credential-access instructions, **THE SYSTEM SHALL** re-scan the decoded payload with the pattern pack and attribute the resulting inner capabilities and `metadata["inner_rules"]` to the finding.
3. **WHEN** a surface file contains bidirectional override characters (`U+202A..U+202E`, `U+2066..U+2069`), **THE SYSTEM SHALL** emit `AV-UNI-002` (`high`).
4. **WHEN** a surface file contains zero-width characters (`ZWSP`, `ZWNJ`, `ZWJ`, `WJ`) other than a leading UTF-8 BOM at index 0, **THE SYSTEM SHALL** emit `AV-UNI-003` (`medium`).
5. **WHEN** a surface file contains 8 or more consecutive variation selectors, **THE SYSTEM SHALL** emit `AV-UNI-005` and decode 256-VS/direct/nibble steganography into `finding.decoded` when printable ASCII is present.
6. **WHEN** a Cyrillic or Greek homoglyph lookalike appears inside an otherwise ASCII Latin word, **THE SYSTEM SHALL** emit `AV-UNI-006` (`medium`).
