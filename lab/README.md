# Lab — intentionally vulnerable PHP app

**FOR LOCAL TESTING ONLY.** This code is deliberately vulnerable (SQLi, XSS,
command injection, unsafe upload, LFI). Never deploy it, never expose it to a
network. See [SAFETY.md](../SAFETY.md).

Used as the target for sandbox proof-of-concept exploits (Phase 2) and the
fix/verify loop (Phase 3).

Run inside the Phalanx sandbox only:

```bash
phalanx sandbox check --project lab
```
