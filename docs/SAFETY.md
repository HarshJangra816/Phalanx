# Safety & Guardrails — Phalanx

Phalanx is a **defensive-only** security tool. These constraints are non-negotiable and are enforced in design, not just policy. Any contribution or feature that weakens them is rejected.

---

## 1. Defensive-only operation

- Phalanx operates **only on checked-out code the user owns or is explicitly authorized to test.**
- It **never** scans, probes, or attacks third-party systems, live sites the user doesn't own, or any target without authorization.
- There is no "scan arbitrary URL/host" mode by design.

## 2. Safe proof-of-concept exploits only

- PoC exploits are of the **read-a-canary / extract-a-marker** class: they prove an impact by reading a planted secret, never by destructive action.
- **Forbidden**: payloads that delete data, drop tables, write webshells, create accounts, pivot, exfiltrate to external servers, or degrade availability.
- All PoCs run **inside the sandbox** with **no outbound network** — exfiltration to an attacker is impossible.

## 3. Sandboxed execution (always on)

- Any LLM-generated code or exploit executes **only** in an ephemeral Docker container.
- Invariants:
  - **No outbound network** from the container.
  - **Ephemeral** per run, destroyed after — no persistent state.
  - **CPU / memory / wall-clock** limits enforced.
  - Only the canary/marker may be read; real user data is never touched.
- The agent has **no arbitrary shell** outside the sandbox wrapper tool surface.

## 4. Full audit logging

- Every agent action, LLM response, tool call, and exploit attempt is written to an append-only JSONL audit log.
- Evidence (canary capture, verification results) is attached to each finding — reproducible.

## 5. Human-in-the-loop by default

- Phalanx **produces patches/PRs — it does not deploy to production.** A human reviews and merges.
- No auto-merge, no auto-deploy to live systems.

## 6. LLM output is untrusted input

- LLM-generated patches and exploits are treated as **untrusted**: validated, sandboxed, and re-verified before acceptance.
- A fix is accepted only when the original exploit **fails** and the app's tests **pass**.

## 7. Responsible disclosure

- When benchmarking against real-world software (e.g., WordPress plugins with known CVEs), Phalanx is used only against **already-public** vulnerabilities for validation — no new exploitation of undisclosed flaws.

## 8. Reporting concerns

If you believe Phalanx can be misused or has a safety gap, open a GitHub issue labeled `safety` or contact the maintainer. Safety reports are prioritized above features.
