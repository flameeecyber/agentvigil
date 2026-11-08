---
inclusion: always
---

# Product

**agentvigil** (`vigil`) is supply-chain security for the instructions an AI agent
obeys: `AGENTS.md`, skills, Kiro steering/specs, MCP server configs, and the
automation those instructions can trigger.

## Who it is for

Security engineers and platform teams who `git clone` unfamiliar repositories into
an agentic IDE, and OSS maintainers who want a reviewable record of what their
repository tells an agent to do.

## The three questions it answers

1. **Did this change?** `vigil.lock` pins the surface; `vigil diff` shows the delta.
2. **What does it let the agent do?** findings carry capabilities (`exec.shell`,
   `fs.credentials`, `net.egress`, `approval.bypass`), not just matched strings.
3. **Who introduced it?** `vigil blame` and `vigil timeline` use read-only git.

## Product shape

- One CLI, zero required dependencies, no daemon, no database.
- The demo is the product: `vigil scan`, `vigil manifest`, `vigil diff`,
  `vigil mcp`, `vigil serve --theme kiroween`.
- Evidence over verdicts: every finding has a span, a rule id, capabilities and,
  when applicable, the decoded payload.

## Non-goals

Sandboxing, model alignment, syscall filtering, and runtime prompt injection from
web content. The threat model is explicit about this; do not imply otherwise in
docs, UI copy or the demo.

## Definition of a good change

A stranger can install it, run the demo, and understand one finding without
reading source code. Precision beats volume; a false positive costs more trust
than a missed LOW.
