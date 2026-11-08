# Spec: Multimodal Smuggling Detector (`AV-IMG-001..010`)

## Problem Statement
Vision-capable coding agents read co-located SVG diagrams, Markdown image references, data URIs, and PNG metadata chunks (`tEXt`, `zTXt`, `iTXt`). Text-only scanners ignore these channels completely (Ghostcommit class).

## Acceptance Criteria
1. **WHEN** an `.svg` file or inline `<svg>` block on the instruction surface contains `<script>` or `<foreignObject>`, **THE SYSTEM SHALL** emit `AV-IMG-001` (`high`).
2. **WHEN** SVG or HTML image markup contains an `on*` event handler (`onload`, `onerror`, `onclick`), **THE SYSTEM SHALL** emit `AV-IMG-002` (`high`).
3. **WHEN** SVG `<text>` is paired with invisible CSS (`display:none`, `opacity:0`, `font-size:0`, `1px`), **THE SYSTEM SHALL** emit `AV-IMG-003` (`medium`).
4. **WHEN** an instruction file references a remote image and surrounding prose instructs the agent to follow/obey/execute instructions in the image, **THE SYSTEM SHALL** emit `AV-IMG-004` (`high`) with capabilities `net.egress`, `agent.deceive`, `agent.self_modify`.
5. **WHEN** a co-located `.png` asset contains `tEXt`, `zTXt`, or `iTXt` chunks with instruction/execution keywords, **THE SYSTEM SHALL** parse the chunks using stdlib `struct` + `zlib` and emit `AV-IMG-010` (`medium`) with the decoded chunk text.
