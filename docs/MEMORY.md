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

- **Current phase:** Phase 1 — FIND (exit test PASSED, awaiting review sign-off to tag `phase-1-complete`)
- **Phase 1 progress:** 5 curated Semgrep rule classes (`rules/php/`), tree-sitter slicer, LLM review layer, dedup/merge, terminal/JSON/SARIF reports, `bench` command + `challenges/` set. Exit test: **10/10 vulns, 0 FP, 0 FN (precision 100% / recall 100%)**. 89/96 tests green (7 skip = Docker daemon down), lint clean.
- **Last completed phase:** Phase 0 — Foundation (tag `phase-0-complete` pushed)
- **Next action:** (1) user review of Phase 1 → fix issues → tag `phase-1-complete` + push; (2) start Phase 2 — PROVE (safe PoC in sandbox)

### Machine environment notes (2026-10-23)

- Docker Desktop is installed at `%LOCALAPPDATA%\Programs\DockerDesktop` (user location, not Program Files).
- First Docker install crashed WSL bootstrap (missing `componentsVersion.json`) + black-screened the laptop (uncapped WSL2 RAM on a 16 GB machine). Fixed by: `%USERPROFILE%\.wslconfig` with `memory=6GB`, `wsl --unregister docker-desktop`, Docker Desktop restart. Engine: Docker 29.9.2, WSL 3.0.3.0.
- **Pagefile crisis (Phase 1):** machine had `AutomaticManagedPagefile=False` with an inadequate/absent pagefile → free virtual memory hit ~0.2 GB under load → `WinError 1455 "paging file is too small"` killing semgrep-core spawns and even PowerShell itself (`OutOfMemoryException`). Fixed by enabling **automatic pagefile management** via elevated script; **user rebooted 2026-10-23 18:30 — fix is live** (free virtual back to ~5 GB; Docker boots fine; full 96/96 suite green with Docker up).
- Docker Desktop may not be running at session start (no processes, WSL distro `Stopped`). Sandbox tests skip gracefully in that case; start `Docker Desktop.exe` and poll `docker info` (~1–2 min) to re-enable them. Verified working post-reboot: engine 29.9.2, WSL VM capped at ~5.8 GB by `.wslconfig`.
- **Windows PowerShell 5.1 stderr artifact:** any stderr line from a native command (e.g. phalanx's `warning: ... ANTHROPIC_API_KEY is not set`) makes the shell wrapper report `Exited with code 1` even when the tool returned 0. Verify real exit codes via `subprocess.run(...)` in Python, not `$LASTEXITCODE` through a PS pipeline.
- `.gitignore` previously had `sandbox/` (unanchored) — would have ignored `src/phalanx/sandbox/`. Now root-anchored `/sandbox/`.

### Phase 0 build notes (2026-10-23)

- Stdlib-only core: no required runtime deps. Extras: `[sandbox]` (docker SDK), `[dev]` (pytest, ruff).
- LLM providers (Anthropic/OpenAI) implemented over stdlib HTTP in `src/phalanx/agent/router.py`; no API key → automatic offline `mock` provider fallback (loop stays runnable).
- Docs moved to `docs/` (README stays at root); `.gitignore` root-anchored `/sandbox/` so `src/phalanx/sandbox/` package isn't ignored.
- Audit logs: `.phalanx/audit-<run_id>.jsonl`, append-only.
- Lab vulnerable app: `lab/public/index.php` (all 5 vuln classes) + `lab/Dockerfile` (php:8.2-cli-alpine + phpunit).
- CLI: `phalanx ask <file> "<question>"` (agent Q&A) · `phalanx scan <path> [--format terminal|json|sarif] [--no-llm]` · `phalanx bench <dir>` · `phalanx sandbox check` · `phalanx doctor`.

### Phase 1 build notes (2026-10-23)

- **Semgrep pathology (important):** a single taint rule with many sinks (esp. mixing function-call and method-call sinks, or `printf($FMT, $VALUE)`-style multi-metavariable varargs patterns) × certain file shapes → **140–180 s core_time on 12-line files**. Fix: split `php.sqli.user-input-to-query` + `php.sqli.oop-user-input-to-query`, and use all-ellipsis `printf(...)`. Integration scans now ~6–15 s. If a scan ever explodes again, bisect rule files one at a time.
- `run_semgrep` passes `--jobs 1` (memory-pressure box; also silences semgrep's OOM "reduce the number of jobs" path) and **retries transient spawn failures** (`_SPAWN_FAILURE_SIGNATURES`: WinError 1455 / paging-file / "Failed to obtain target files from semgrep-core" / OOM text) with backoff.
- `semgrep_available()` resolves the binary from `sys.executable`'s scripts dir as venv fallback — PATH is often unmodified when invoking python by explicit path.
- **tree-sitter API:** package exposes `tree_sitter_php.language_php()` (not `.language()`); wrap in `tree_sitter.Language(...)`.
- **Taint is intra-procedural:** flows that enter through *function parameters* (controller → model) are NOT flagged; only direct superglobal-to-sink flows (incl. variable chains/interpolation, which taint does track). Challenge set is built on direct flows; param/second-order flows are LLM-review territory (Phase 2+).
- LLM review auto-skips with a recorded reason in `llm_errors` (`skipped: budget exhausted…` / `skipped: offline mock provider (no API key)`) — deterministic findings always survive; review sees ONE function slice at a time, max `llm_max_slices=20`.
- Benchmark scoring (`bench.py`): TP = same file + class (+ line within ±5 when given); anything unmatched = FP, including findings on `clean_files`. Run: `phalanx bench challenges`.
- PowerShell 5.1 traps (cost real debugging time): `2>&1` merges stderr error-records into JSON pipes; `>` writes **UTF-16**; `$var` inside double-quoted `python -c "..."` is expanded by PS (breaks `$schema` etc.). Prefer `-c` single-file scripts or heredoc-free files; validate via exit codes, not stderr silence.

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
