# PRD — Phalanx

**Status:** Draft v1 · **Last updated:** 2026-10-23

---

## 1. Problem

AI has flipped the economics of attacking PHP web software:

- **AI finds bugs faster than humans patch them.** PHP2Shell (CVE-2026-109618) hid in PHP for over a decade; AI tools surfaced it in days. ~1.5M of 2.6M PHP hosts were exposed when it was disclosed.
- **AI attacks at machine speed.** Autonomous agents are being used to scan and compromise sites at scale far beyond human defender capacity.
- **Defenders patch at human speed.** Most exposed operators are on legacy code, outdated plugins, or shared hosting with no security staff. Patches exist — applying them safely is the bottleneck.

Existing tools fail at the last mile:

- **Scanners** (Semgrep, GitHub scanning, Dependabot) find problems but produce triage load — no fixes, lots of noise. The security community is already drowning in AI-generated false-positive vuln reports.
- **Autofix tools** (Snyk, Semgrep autofix) offer shallow or dependency-only fixes with no proof they work.
- **AI coding assistants** (Copilot, Cursor) can edit code but have no security focus and no verification loop — a "fix" that breaks the app or fails to close the hole is worse than no fix.

**The missing piece: an agent that finds a vulnerability, proves it is real, fixes it, and proves the fix works — without regressions.**

## 2. Product statement

> Phalanx is a defensive security tool that autonomously finds, proves, fixes, and verifies vulnerabilities in PHP code. Every reported finding carries exploit evidence; every proposed fix carries proof it closes the hole and breaks nothing.

## 3. Users

| Persona | Need | How Phalanx helps |
|---|---|---|
| **Solo dev / small team** with AI-generated ("vibe-coded") PHP | Ship fast without shipping holes | CI gate that finds and fixes vulns pre-merge |
| **WordPress plugin/theme maintainer** | Known-CVE remediation in their own code | Find + fix + verified patch as a PR |
| **Agency / freelancer** maintaining many client sites | No time for manual audits | Batch scanning with verified reports |
| **Security-conscious OSS maintainer** | Triage without false-positive flood | Exploit-proven findings only |

**Explicit non-user:** anyone wanting to attack systems they don't own. Phalanx is defensive-only (see SAFETY.md).

## 4. Goals

1. **Find** real vulnerabilities across the top PHP vuln classes with high precision.
2. **Prove** findings with safe, sandboxed proof-of-concept exploits — suppressing false positives.
3. **Fix** with minimal, semantic patches (not string-escaping band-aids).
4. **Verify** each fix: re-exploit must fail AND the app's test suite must pass.
5. **Stay cheap**: deterministic-first, LLM only where it matters; hard token budget caps.
6. **Stay safe**: defensive-only operation, sandboxed execution, full audit logging.

## 5. Non-goals (v1)

- Scanning or attacking systems the user does not own.
- Auto-deploying fixes to production live sites (output is a patch/PR, human merges).
- Coverage of every PHP vulnerability class (v1: SQLi, XSS, command injection, file upload, path traversal/LFI).
- Java/Python/Node support (PHP only, v1).
- Replacing a WAF (runtime protection is out of scope; this is code-level remediation).

## 6. Features by phase

### Phase 0 — Foundation
- Python package scaffold, CLI skeleton (`phalanx scan|fix`)
- Docker sandbox lifecycle (create → run → destroy), no-outbound-network, resource caps
- LLM agent tool-loop: `read_file`, `edit_file`, `run_scan`, `run_exploit`, `run_tests`
- Tiered model config (provider-agnostic, Claude default)

### Phase 1 — FIND
- Curated Semgrep PHP rulesets for the 5 target vuln classes
- tree-sitter-php parsing + function-level slicing (send only relevant code to LLM)
- LLM review layer for logic flaws (auth bypass, IDOR) rules can't catch
- Confidence scoring, dedup/merge of deterministic + LLM findings
- Reports: terminal, JSON, SARIF (GitHub code-scanning compatible)

### Phase 2 — PROVE
- Agent-authored safe PoC exploit per finding (read-a-canary / extract-a-marker class only)
- Sandboxed execution, per-run ephemeral containers
- Finding promotion: CONFIRMED vs REJECTED (false positive)
- Full audit log of every action and exploit attempt

### Phase 3 — FIX + VERIFY
- Minimal semantic patch generation
- Verification gate: re-exploit FAILS ∧ test suite PASSES
- Bounded retry loop (re-analyze → re-patch → re-verify, max 3 attempts)
- Output: unified diff + PR-ready markdown (before/after + evidence)

### Phase 4 — Distribution
- CLI polish: `--budget`, `--sandbox`, `--format`, config file
- GitHub Action (composite): scan on push/PR, comment findings, open fix PRs
- Web dashboard: FastAPI + React, connect repo, findings grid, "apply fix" → PR

### Phase 5 — Validation
- Benchmarks against real vulnerable WP plugin versions (5–10 known CVEs)
- Public challenge set: 25–30 samples (5 classes × easy/medium/hard) with expected fixes
- Published benchmark: precision, fix-rate, regression-rate vs Semgrep-only baseline

## 7. Success metrics

| Metric | Target | Why it matters |
|---|---|---|
| Precision (confirmed / reported) | > 85% | False positives kill trust in security tools |
| Fix success rate | ≥ 60% of confirmed vulns | The product's core promise |
| Regression rate | **0** (hard gate) | A fix that breaks the app is a fail |
| Token cost per mid-size scan | Cents, not dollars | Viability + reviews well |
| Time-to-fix (demo) | ~90 seconds vs ~1 hour human | The headline |

## 8. Constraints

- **Defensive-only**: operates on checked-out code the user owns / is authorized to test. No third-party scanning.
- **Safe exploits**: proof-of-concept class only (read canary, extract marker). No destructive payloads.
- **Sandbox always on**: LLM-generated code and exploits execute only inside isolated Docker containers.
- **Provider-agnostic LLM layer**: default Claude tiered (Haiku triage → Sonnet fix), swappable via config.

## 9. Risks & mitigations

| Risk | Mitigation |
|---|---|
| False positives erode trust | PROVE stage mandatory; only confirmed findings surface |
| LLM "fixes" that don't fix or break code | VERIFY gate (re-exploit + test suite); bounded retries |
| Token cost blowup | Deterministic-first, slicing, caching, `--budget` cap |
| Misuse (offensive use) | Defensive-only design, safe PoC class, audit logs, license/ToS |
| Scope creep to "all vulns / all languages" | Hard v1 scope: 5 classes, PHP only |

## 10. Open questions

- License: MIT vs Apache-2.0 (Apache adds explicit patent grant)?
- Name of the canary mechanism for PoC exploits (to be standardized in Phase 2)?
- Minimum Python version floor (3.11 planned)?
