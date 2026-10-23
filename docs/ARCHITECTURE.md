# Architecture — Phalanx

**Status:** Draft v1 · **Last updated:** 2026-10-23

---

## 1. Design principles

1. **Deterministic-first, LLM-second.** Static analysis does the bulk work for free; the LLM only sees short, pre-filtered snippets. This is the token-cost backbone.
2. **No finding without proof.** The LLM's opinion is a *hypothesis*; only a successful sandboxed PoC makes it CONFIRMED.
3. **No fix without verification.** A patch is accepted only when the original exploit fails AND the app's tests pass.
4. **Everything sandboxed, everything logged.** Any LLM-generated code or exploit runs only in ephemeral, network-isolated Docker containers. Every agent action is recorded.
5. **Provider-agnostic LLM layer.** Model choice is config, not architecture.

## 2. High-level component diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        Phalanx CLI / Action / API                │
└──────────────────────────────┬──────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────┐
│                     Agent Core (Python)                          │
│   State machine: FIND → PROVE → FIX → VERIFY → DELIVER           │
│   Tool loop: read_file · edit_file · run_scan · run_exploit ·    │
│              run_tests · report                                  │
│   Token budget meter · audit logger · model router               │
└───────┬──────────────────────────────┬───────────────────────────┘
        ↓                              ↓
┌───────────────────────┐   ┌──────────────────────────────────────┐
│   Scanner Layer       │   │   Sandbox (Docker)                    │
│   • Semgrep rules     │   │   • Ephemeral PHP app container       │
│     (5 vuln classes)  │   │   • No outbound network               │
│   • tree-sitter-php   │   │   • CPU / mem / time caps             │
│     parse + slice     │   │   • Runs PoC exploit (pre & post fix) │
│   • LLM code review   │   │   • Runs app test suite (PHPUnit)     │
│     (logic flaws)     │   │   • Canary / marker mechanism         │
└───────────┬───────────┘   └──────────────────┬───────────────────┘
            ↓                                  ↓
┌─────────────────────────────────────────────────────────────────┐
│                      Findings & Evidence Store                   │
│   Finding = { location, class, confidence, status,               │
│               poc_evidence, patch_diff, verification_results }   │
└──────────────────────────────┬──────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────────┐
│                          Output Layer                            │
│   Terminal report · JSON · SARIF · PR-ready Markdown · (later:   │
│   GitHub Action comments/PRs · Web dashboard)                    │
└─────────────────────────────────────────────────────────────────┘
```

## 3. Components

### 3.1 Scanner Layer (Phase 1)
- **Semgrep rules**: curated PHP rulesets covering SQL injection, XSS, command injection, unsafe file upload, path traversal/LFI. Runs as a subprocess; output parsed into normalized findings.
- **tree-sitter-php**: parse PHP, locate flagged lines, extract the enclosing **function-level slice** so the LLM receives ~50–150 lines, never whole files.
- **LLM review**: reviews slices for logic flaws (auth bypass, IDOR, missing access checks) and second-guesses deterministic hits. Output is a hypothesis with reasoning + confidence.

### 3.2 Agent Core (Phase 0)
- Python state machine (LangGraph-style) driving the pipeline stages.
- Tool-calling loop with a fixed tool surface (see §2). The agent never gets shell access outside the sandbox wrapper.
- **Model router**: per-stage model selection from config — default `triage: claude-haiku`, `fix: claude-sonnet`; provider-agnostic interface.
- **Token budget meter**: counts usage per run; stops gracefully at the `--budget` cap with a partial report.
- **Audit logger**: append-only JSONL of every tool call, LLM response, and exploit attempt.

### 3.3 Sandbox (Phase 2)
- Ephemeral Docker container running the target PHP app (built from a provided Dockerfile or the bundled lab image).
- **Network: none** (no outbound; exploit cannot reach the internet or LAN).
- Resource caps: CPU, memory, wall-clock timeout per execution.
- Two runners:
  - `run_exploit`: executes agent-authored safe PoC; returns structured result (status, captured canary/marker, logs).
  - `run_tests`: executes the app's PHPUnit suite; returns pass/fail + failures.
- **Canary/marker mechanism** (Phase 2 to finalize): a planted secret (file contents / DB row) that a successful exploit must exfiltrate — proving impact without touching real data.

### 3.4 Fixer (Phase 3)
- LLM generates a **minimal semantic patch** (unified diff) for a CONFIRMED finding.
- Parsed and applied to a working copy; re-verified in sandbox.
- **Retry loop**: if verification fails, the agent re-analyzes with the failure evidence, re-patches — max 3 attempts, then surfaces as UNFIXED with reasons.

### 3.5 Output Layer (Phase 1 → 4)
- Terminal (human), JSON (machine), SARIF (GitHub code scanning), Markdown (PR body).
- Phase 4 adds: GitHub Action wrapper, FastAPI + React dashboard.

## 4. Data model (core)

```
Finding {
  id, file, start_line, end_line,
  vuln_class,            # sqli | xss | cmdi | upload | lfi | logic
  confidence,            # 0..1
  status,                # HYPOTHESIS | CONFIRMED | REJECTED | FIXED | UNFIXED
  evidence,              # PoC exploit script + captured output (canary)
  patch,                 # unified diff
  verification,          # { reexploit: FAILED|PASSED, tests: PASSED|FAILED, attempts }
  tokens_used, model
}
```

## 5. Tech stack

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.11+ | Agent strength, ecosystem |
| Agent | LangGraph-style state machine over Anthropic/OpenAI SDK | Provider-agnostic |
| Static analysis | Semgrep (subprocess) + tree-sitter-php | Deterministic core |
| Sandbox | Docker SDK for Python | Ephemeral, isolated |
| PHP tests | PHPUnit (in-container) | Regression gate |
| Reports | SARIF, JSON, Markdown | SARIF = free GitHub integration |
| Dashboard (v4) | FastAPI + React | Later phase |
| Packaging | `pipx`/PyPI CLI; composite GitHub Action | Phase 4 |

## 6. Token strategy (critical)

```
Repo (50 files)
  → Semgrep + tree-sitter (FREE)
  → 12 hotspot slices (~2–3k tokens each)
  → triage model (cheap) filters → 5 confirmed
  → fix model (strong) sees ONLY the 5 slices + their evidence
```

- **Function-level slicing** — LLM never reads whole files.
- **Prompt caching** — Anthropic `cache_control` for stable prefixes (system prompt, rules context).
- **File-hash memoization** — unchanged files are never re-sent; re-scans ≈ free.
- **`--budget N`** — hard token cap; graceful stop with partial results.
- **Deterministic-first** — most vulns never reach the LLM at all.

## 7. Sandbox security invariants

1. No outbound network from the container (exploit cannot exfiltrate to an attacker).
2. Ephemeral container per run; destroyed after; no persistent state.
3. CPU / memory / wall-clock limits enforced.
4. Only the canary/marker mechanism may be read — the exploit never touches real user data.
5. Full audit trail of every execution.

## 8. Repo structure (target)

```
phalanx/
├── pyproject.toml
├── docs
│   └── README.md · PRD.md · ARCHITECTURE.md · ROADMAP.md · SAFETY.md · MEMORY.md
├── src/phalanx/
│   ├── cli.py
│   ├── agent/          # state machine, tool loop, model router, budget, audit
│   ├── scanner/        # semgrep runner, tree-sitter slicer, LLM review
│   ├── sandbox/        # docker lifecycle, run_exploit, run_tests, canary
│   ├── fixer/          # patch generation + verification + retry
│   └── output/         # terminal, json, sarif, markdown
├── rules/              # curated semgrep PHP rulesets
├── lab/                # intentionally-vulnerable PHP app + Dockerfile
├── challenges/         # own vulnerable samples + expected fixes (benchmark)
└── tests/              # unit tests for phalanx itself
```

## 9. Open design questions

- Exact canary/marker protocol (file-based vs DB-row-based vs both) — decide in Phase 2.
- Whether tree-sitter extraction is sufficient or a full PHP AST (nikic/php-parser via subprocess) is needed for logic-flaw slicing.
- How to detect "app has no test suite" — skip test gate or synthesize a smoke test?
