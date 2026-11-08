# Design: multimodal smuggling

## Overview

Vision-capable agents read SVG diagrams and co-located images. Text-only scanners
skip that channel. This detector treats image markup as instruction text and PNG
metadata as a possible payload carrier.

## Channels

1. **SVG / inline `<svg>`** — active content (`<script>`, `<foreignObject>`),
   event handlers (`on*`), and text made invisible with CSS (`display:none`,
   `opacity:0`, `font-size:0`, 1px sizing).
2. **Markdown image references** — a remote image is LOW on its own; it becomes
   HIGH only when surrounding prose delegates behaviour to the image ("follow the
   instructions in the diagram"). This gate is the main false-positive control.
3. **Data URIs** — decoded and scanned with the same rules.
4. **PNG metadata** — `tEXt`, `zTXt`, `iTXt` chunks parsed with `struct` and
   `zlib`; instruction-like keywords raise `AV-IMG-010` with the decoded chunk text.

## Decisions

- **No image decoding.** SVG is text; PNG chunks are bytes. No Pillow, no OCR, no
  model call — keeps the core stdlib-only and the scan offline.
- **Prose gates remote images.** Logos in docs are common; delegation is not.
- **Chunk parsing is defensive.** Truncated files, bad CRCs and unknown chunk
  types return no findings instead of raising.
- **Assets are discovered separately** from instruction files so a README can
  reference an image that is scanned even when it lives in `assets/`.

## Properties (PBT)

- `scan_png_chunks` never raises on arbitrary bytes.
- A benign `tEXt` title produces no finding.
- Delegation prose without a remote image produces no `AV-IMG-004`.

## Failure modes

- A remote image whose payload is only readable by a vision model cannot be
  inspected offline; the finding names the delegation, not the content.
- CSS obfuscation beyond the listed properties is not detected; `--strict` keeps
  the noisy remote-image rule available to auditors.
