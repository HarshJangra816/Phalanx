# Rules — curated Semgrep PHP rulesets

Ships in **Phase 1**: SQLi, XSS, command injection, file upload, path traversal/LFI.

`phalanx scan` picks up every `*.yml` / `*.yaml` in this directory
(recursively). Keep each rule's `id` containing its vuln class keyword
(`sqli`, `xss`, `cmdi`, `upload`, `lfi`) so findings classify correctly.
