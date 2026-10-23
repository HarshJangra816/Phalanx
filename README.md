# 🛡️ Phalanx

**An AI security engineer for PHP that finds, proves, fixes, and verifies vulnerabilities — at machine speed.**

> In the wake of AI-discovered flaws like **PHP2Shell (CVE-2026-109618)**, attackers patch-hunt at machine speed while defenders patch at human speed. Phalanx flips that: an autonomous agent that not only *finds* vulnerabilities but generates a fix and **proves the fix works** by re-exploiting it.

---

## Why Phalanx is different

| Existing tool | What it does | Why it's not enough |
|---|---|---|
| Dependabot / GitHub scanning | Flags known CVEs | Dependency bumps only, never fixes app code |
| Snyk autofix | Suggests fixes | Weak on application-logic vulns |
| Semgrep autofix | Regex-level rewrites | No semantic understanding, no proof |
| Copilot / Cursor | Can edit code | No security focus, no verification loop |

**Phalanx closes the loop nobody else closes: FIND → PROVE → FIX → VERIFY.**

The fix is only accepted when:
1. A safe proof-of-concept exploit that previously **succeeded** now **fails**, and
2. The application's own test suite still **passes** (zero regressions).

---

## The core loop

```
PHP repo
   ↓
1. FIND      Semgrep + tree-sitter scan (deterministic, FREE)
             + LLM review of flagged code (logic flaws rules can't see)
   ↓
2. PROVE     Sandbox (Docker) reproduces the vuln with a SAFE PoC exploit
             → CONFIRMED or rejected as FALSE POSITIVE
   ↓
3. FIX       LLM generates a minimal semantic patch
             (parameterized query / auth check / path canonicalization)
   ↓
4. VERIFY    Re-run the exploit → must now FAIL
             Run the app's test suite → must PASS
             (failed? agent iterates — bounded retry loop)
   ↓
5. DELIVER   PR-ready diff with evidence + explanation
```

## Token-efficient by design

Most files **never touch an LLM**. The deterministic layer does the bulk work; a cheap model kills false positives; the strong model only ever sees the few confirmed snippets.

```
50-file repo → Semgrep scan (free) → 12 hotspots
             → Haiku triage (cheap) → 5 confirmed
             → Sonnet fix + verify (only here)
```

- Prompt caching + file-hash memoization (re-scans of unchanged files ≈ free)
- Function-level slicing — only the vulnerable function is sent, never whole files
- `--budget N` hard token cap per run

## Quickstart (Phase 0 preview)

```powershell
# install (sandbox extra adds the Docker SDK)
pip install -e ".[sandbox]"

# environment check
phalanx doctor

# ask the agent about a PHP file (uses ANTHROPIC_API_KEY; offline mock without it)
phalanx ask lab/public/index.php "what vulnerabilities does this file contain?" --no-sandbox

# prove the sandbox has no outbound network (Phase 0 exit test)
phalanx sandbox check --project lab

# deterministic scan (Phase 1 ships the rules)
phalanx scan lab
```

Requires Python 3.11+. Docker Desktop is needed only for `sandbox` commands and PoC execution.

## Roadmap

- [ ] **Phase 0** — Foundation: scaffold, Docker sandbox, agent tool-loop
- [ ] **Phase 1** — FIND: Semgrep rules + LLM review, SARIF/Markdown reports
- [ ] **Phase 2** — PROVE: sandboxed safe PoC exploits, false-positive suppression
- [ ] **Phase 3** — FIX + VERIFY: semantic patches, re-exploit-must-fail gate
- [ ] **Phase 4** — Distribution: CLI polish → GitHub Action → Web dashboard
- [ ] **Phase 5** — Validation: real WP plugin CVEs, public challenge set, benchmark

See [docs/ROADMAP.md](docs/ROADMAP.md) for exit criteria per phase.

## Documentation

| File | Purpose |
|---|---|
| [docs/PRD.md](docs/PRD.md) | Product requirements — problem, users, features, metrics |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design, components, tech stack, data flow |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phased build plan with exit tests |
| [docs/SAFETY.md](docs/SAFETY.md) | Non-negotiable guardrails (defensive-only tool) |
| [docs/MEMORY.md](docs/MEMORY.md) | Persistent project context for AI-assisted development |

## Status

🚧 **Phase 0 — code complete, exit test pending.** Package, CLI (`ask|scan|fix|sandbox|doctor`), Docker sandbox, agent tool-loop, budget/audit all built (45+ tests green). Awaiting sandbox network-isolation proof on a Docker host before the `phase-0-complete` tag. Not yet usable for real scanning — Phase 1 ships the rules.

## License

MIT (planned).
