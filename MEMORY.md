# MEMORY — Phalanx

Persistent project context so any AI agent (or future contributor) picking this up knows the decisions, constraints, and current state **without re-deriving them**. Update this file at the end of every phase.

---

## What this project is

**Phalanx** — an AI security engineer for PHP that **finds, proves, fixes, and verifies** vulnerabilities at machine speed. The differentiator vs Semgrep/Snyk/Copilot: it closes the loop nobody else closes — a fix is only accepted when the original exploit **fails** and the app's tests **pass**.

Origin: motivated by the AI-driven PHP hacking wave (PHP2Shell / CVE-2026-109618) — attackers use AI at machine speed, defenders patch at human speed. Phalanx makes defenders equally fast.

## Locked decisions

| Decision | Choice |
|---|---|
| Name / CLI | **Phalanx** / `phalanx` |
| Location | `C:\Users\Harsh\Desktop\Project-AI\Phalanx` (own repo, **not** inside Luxion) |
| Language | Python 3.11+ orchestrator |
| LLM strategy | **Tiered Claude** (Haiku triage → Sonnet fix), **provider-agnostic** underneath |
| Token control | Deterministic-first, function-level slicing, prompt caching, `--budget` cap |
| Surfaces | CLI (v1) → GitHub Action (v2) → Web dashboard (v3) |
| Test targets | Lab app → own challenge set → real vulnerable WP plugins |
| Scope (v1) | 5 vuln classes: SQLi, XSS, command injection, file upload, path traversal/LFI · PHP only |
| Push convention | Push to GitHub **after each phase** (`phase-N-complete` tag) |

## Non-negotiable guardrails (see SAFETY.md)

- **Defensive-only**: only on code the user owns / is authorized to test. No third-party scanning.
- **Safe PoC only**: read-a-canary / extract-a-marker class. No destructive payloads.
- **Always sandboxed**: ephemeral Docker, no outbound network, resource caps, full audit log.
- **Human-in-the-loop**: produces patches/PRs, never auto-deploys to production.

## Core loop (memorize this)

```
FIND (Semgrep + tree-sitter, free) → PROVE (sandboxed safe PoC → CONFIRMED)
→ FIX (minimal semantic patch) → VERIFY (re-exploit FAILS ∧ tests PASS)
→ DELIVER (PR-ready diff + evidence)
```

## Current status

- **Current phase:** Phase 0 — Foundation
- **Phase 0 progress:** docs created (README, PRD, ARCHITECTURE, ROADMAP, SAFETY, MEMORY); scaffold + sandbox + agent loop pending
- **Last completed phase:** none yet
- **Next action:** build the Python package scaffold + Docker sandbox + agent tool-loop

## Success metrics targets

Precision > 85% · Fix rate ≥ 60% of confirmed vulns · **0 regressions** · token cost per mid-size scan in cents · demo: "fixed in 90 seconds what takes an hour"

## Key architecture facts

- **Deterministic-first**: most files never touch an LLM — Semgrep does the bulk work; cheap model triages; strong model only sees the few confirmed slices.
- **Function-level slicing** (tree-sitter-php): LLM receives ~50–150 lines, never whole files.
- **Model router**: per-stage model from config; provider-agnostic interface.
- **Findings data model**: `{ location, vuln_class, confidence, status(HYPOTHESIS|CONFIRMED|REJECTED|FIXED|UNFIXED), evidence, patch, verification, tokens_used, model }`.
- **Sandbox tools**: `run_exploit` (safe PoC) and `run_tests` (PHPUnit) — the only execution paths.

## Tech stack

Python 3.11+ · LangGraph-style agent over Anthropic/OpenAI SDK · Semgrep (subprocess) · tree-sitter-php · Docker SDK for Python · PHPUnit in-container · SARIF/JSON/Markdown output · FastAPI + React (dashboard, later)

## How to extend this file

After each phase: update **Current status**, tick boxes in ROADMAP.md, and record any new locked decisions or course-corrections here so the next session starts warm.
