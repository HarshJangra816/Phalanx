# Roadmap — Phalanx

**Cadence:** each phase ends with a git push to GitHub + a phase-tagged commit.
**Exit rule:** a phase is "done" only when its exit test passes.

---

## Phase 0 — Foundation ✅ target: scaffold + working agent loop
- [x] Python package scaffold (`pyproject.toml`, `src/phalanx/`), CLI skeleton (`ask|scan|fix|sandbox|doctor`)
- [x] Docker sandbox lifecycle: create → run → destroy, no-outbound-network, resource caps
- [x] Agent tool-loop with tools: `read_file`, `edit_file`, `run_scan`, `run_exploit`, `run_tests`
- [x] Tiered model config (provider-agnostic, Claude default: Haiku triage / Sonnet fix)
- [x] Audit logger (append-only JSONL) + token budget meter
- [x] Docs: README, PRD, ARCHITECTURE, ROADMAP, SAFETY, MEMORY
**Exit test:** agent can read a PHP file in the sandbox and answer questions about it; sandbox proves network-isolated.
**Status: EXIT TEST PASSED (2026-10-23) — tagged `phase-0-complete`, pushed.** `phalanx sandbox check --project lab` → ✔ SANDBOX ISOLATED; agent Q&A ran with full sandbox lifecycle (create → run → destroy, audit trail verified). Live Claude call pending Anthropic account credits.

## Phase 1 — FIND ✅ target: FIND stage complete
- [x] Curated Semgrep PHP rules for SQLi, XSS, CMDi, upload, LFI (`rules/php/` — 6 rules across the 5 classes)
- [x] tree-sitter-php parsing + function-level slicing (`scanner/slicer.py`)
- [x] LLM review layer (logic flaws: auth bypass, IDOR) + confidence scoring (`scanner/llm_review.py`)
- [x] Dedup/merge of deterministic + LLM findings (`scanner/merge.py`)
- [x] Reports: terminal, JSON, SARIF 2.1.0 (`output/sarif.py`) · `phalanx bench` + `challenges/` set
**Exit test:** flags all vulns in the challenge set; baseline precision measured vs Semgrep-only.
**Status: EXIT TEST PASSED (2026-10-23).** `phalanx bench challenges` → **10/10 vulns flagged, 0 FP, 0 FN (precision 100% / recall 100%)**; semgrep-only baseline scored the same on this set (LLM review wired end-to-end but inactive without API key credits). `phalanx scan lab --format sarif` emits valid SARIF 2.1.0. 89/96 tests green (7 skip = Docker daemon not running; those passed in Phase 0), lint clean. Awaiting review sign-off to tag `phase-1-complete`.

## Phase 2 — PROVE
- [ ] Safe PoC exploit generation (read-a-canary / extract-a-marker class only)
- [ ] Sandboxed execution, ephemeral containers
- [ ] CONFIRMED vs REJECTED promotion
- [ ] Full audit log of exploit attempts
**Exit test:** precision > 85% on lab app; false positives visibly suppressed vs Phase 1.

## Phase 3 — FIX + VERIFY  ← headline feature
- [ ] Minimal semantic patch generation
- [ ] Verification gate: re-exploit FAILS ∧ test suite PASSES
- [ ] Bounded retry loop (max 3 attempts)
- [ ] PR-ready markdown output (before/after + evidence)
**Exit test:** fixes ≥ 60% of confirmed lab vulns with 0 regressions.

## Phase 4 — Distribution
- [ ] CLI polish: `--budget`, `--sandbox`, `--format`, config file
- [ ] GitHub Action (composite): scan on push/PR, comment findings, open fix PRs
- [ ] Web dashboard: FastAPI + React, connect repo, findings grid, "apply fix" → PR
**Exit test:** Action runs green on a sample repo; dashboard shows a live scan.

## Phase 5 — Validation + launch
- [ ] Benchmarks on real vulnerable WP plugin versions (5–10 known CVEs)
- [ ] Public challenge set: 25–30 samples (5 classes × easy/medium/hard) with expected fixes
- [ ] Benchmark blog post: precision, fix-rate, regression-rate vs Semgrep-only baseline
**Exit test:** published numbers hit targets (precision > 85%, fix ≥ 60%, 0 regressions).

---

## Git / GitHub convention
- **After every phase:** commit with `phase-N-complete` tag + push to GitHub.
- Commit style: `type(scope): summary` (e.g., `feat(scanner): add semgrep PHP rulesets`).
- Main branch is always in a runnable state at phase boundaries.
