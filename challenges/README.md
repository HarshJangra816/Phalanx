# Challenge set — ground truth for the FIND stage

**5 vuln classes × 3 variants** (easy = direct flow, medium = chained flow,
clean = secure pattern). Local testing only.

Score any scan against `expected.json`:

```powershell
phalanx bench challenges
```

The bench prints precision/recall for **semgrep-only (baseline)** vs
**Phalanx (find stage)** — the Phase 1 exit-test metric.

Rules for editing this set:
- Each vuln file contains exactly ONE intended vulnerability (the `clean`
  files must contain none) — extra findings count as false positives.
- Keep `expected.json` line numbers in sync (±5 tolerance applies).
