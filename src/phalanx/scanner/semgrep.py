"""Semgrep subprocess runner — the deterministic backbone of the FIND stage."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from phalanx.findings import Finding, VulnClass

_RULE_ID_TO_CLASS = {
    "sqli": VulnClass.SQLI,
    "sql-injection": VulnClass.SQLI,
    "xss": VulnClass.XSS,
    "cross-site-scripting": VulnClass.XSS,
    "cmdi": VulnClass.CMDI,
    "command-injection": VulnClass.CMDI,
    "upload": VulnClass.UPLOAD,
    "file-upload": VulnClass.UPLOAD,
    "lfi": VulnClass.LFI,
    "path-traversal": VulnClass.LFI,
}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    rules_used: list[str] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def ok(self) -> bool:
        return not self.error


def semgrep_available() -> tuple[bool, str]:
    path = shutil.which("semgrep")
    if not path:
        return False, "semgrep binary not on PATH (pip install semgrep)"
    return True, path


def _classify(rule_id: str) -> VulnClass:
    rid = rule_id.lower()
    for needle, vuln in _RULE_ID_TO_CLASS.items():
        if needle in rid:
            return vuln
    return VulnClass.UNKNOWN


def _default_rules_dir() -> Path:
    # repo-root `rules/` directory (ships with the package checkout)
    return Path(__file__).resolve().parents[3] / "rules"


def run_semgrep(target: Path, rules_dir: Path | None = None,
                timeout: int = 300) -> ScanResult:
    """Run semgrep against `target` with Phalanx PHP rules; normalize findings."""
    available, info = semgrep_available()
    if not available:
        return ScanResult(error=info)

    rules_dir = rules_dir or _default_rules_dir()
    rule_files = sorted(rules_dir.rglob("*.yml")) + sorted(rules_dir.rglob("*.yaml"))
    if not rule_files:
        return ScanResult(error=f"no semgrep rules found in {rules_dir} (Phase 1 ships them)")

    cmd = ["semgrep", "scan", "--json", "--metrics=off", "--quiet",
           "--timeout", "60"]
    for rf in rule_files:
        cmd += ["--config", str(rf)]
    cmd.append(str(target))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              check=False)
    except subprocess.TimeoutExpired:
        return ScanResult(error=f"semgrep timed out after {timeout}s")
    except OSError as exc:
        return ScanResult(error=f"failed to run semgrep: {exc}")

    try:
        payload = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return ScanResult(error=f"semgrep produced invalid JSON: {proc.stdout[:500]}")

    findings: list[Finding] = []
    for res in payload.get("results", []):
        rule_id = res.get("check_id", "")
        start = res.get("start", {}).get("line", 0)
        findings.append(Finding(
            file=res.get("path", str(target)),
            start_line=start,
            end_line=res.get("end", {}).get("line", start),
            vuln_class=_classify(rule_id),
            confidence=0.7,
            message=res.get("extra", {}).get("message", rule_id),
            source="semgrep",
        ))

    error = ""
    if proc.returncode not in (0, 1) and not findings:  # 1 = findings present
        semgrep_errors = payload.get("errors", [])
        detail = (proc.stderr or str(semgrep_errors))[:500]
        error = f"semgrep exit {proc.returncode}: {detail}"

    return ScanResult(findings=findings, error=error,
                      rules_used=[str(r) for r in rule_files],
                      files_scanned=len(payload.get("paths", {}).get("scanned", [])))
