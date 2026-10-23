"""SARIF 2.1.0 report — free GitHub code-scanning integration (ARCHITECTURE.md §3.5)."""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any

from phalanx.findings import Finding, FindingStatus, VulnClass

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION = "2.1.0"

_RULE_TITLES = {
    VulnClass.SQLI: "SQL Injection",
    VulnClass.XSS: "Cross-Site Scripting",
    VulnClass.CMDI: "OS Command Injection",
    VulnClass.UPLOAD: "Unrestricted File Upload",
    VulnClass.LFI: "Path Traversal / Local File Inclusion",
    VulnClass.LOGIC: "Security Logic Flaw",
    VulnClass.UNKNOWN: "Potential Security Issue",
}

_RULE_DOCS = {
    VulnClass.SQLI: "CWE-89",
    VulnClass.XSS: "CWE-79",
    VulnClass.CMDI: "CWE-78",
    VulnClass.UPLOAD: "CWE-434",
    VulnClass.LFI: "CWE-22",
    VulnClass.LOGIC: "CWE-840: Business Logic Errors",
    VulnClass.UNKNOWN: "CWE-1032",
}


def _level(finding: Finding) -> str:
    if finding.status == FindingStatus.CONFIRMED:
        return "error"
    if finding.status == FindingStatus.REJECTED:
        return "note"
    return "warning"


def _rule_id(finding: Finding) -> str:
    return f"phalanx.php.{finding.vuln_class.value}"


def _uri(file: str, root: Path | None) -> str:
    p = Path(file)
    if root is not None:
        with contextlib.suppress(ValueError):
            p = p.resolve().relative_to(root.resolve())
    return p.as_posix()


def to_sarif(findings: list[Finding], *, tool_version: str = "0.1.0",
             root: Path | None = None) -> dict[str, Any]:
    """Convert findings to a SARIF 2.1.0 dict (run object)."""
    classes_in_play = sorted({f.vuln_class for f in findings},
                             key=lambda c: c.value)
    rules = []
    rule_index: dict[str, int] = {}
    for klass in classes_in_play:
        rule_index[_rule_id(Finding(file="", start_line=0, end_line=0,
                                    vuln_class=klass))] = len(rules)
        rules.append({
            "id": f"phalanx.php.{klass.value}",
            "name": _RULE_TITLES[klass],
            "shortDescription": {"text": f"{_RULE_TITLES[klass]} in PHP code"},
            "helpUri": f"https://cwe.mitre.org/data/definitions/"
                       f"{_RULE_DOCS[klass].split('-')[1]}.html",
            "properties": {"tags": ["security", klass.value],
                           "precision": "high"},
        })

    results = []
    for f in sorted(findings, key=lambda x: (x.file, x.start_line)):
        rid = _rule_id(f)
        region: dict[str, Any] = {"startLine": f.start_line}
        if f.end_line and f.end_line > f.start_line:
            region["endLine"] = f.end_line
        results.append({
            "ruleId": rid,
            "ruleIndex": rule_index.get(rid, 0),
            "level": _level(f),
            "message": {"text": f.message or "Potential security issue"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(f.file, root)},
                    "region": region,
                },
            }],
            "partialFingerprints": {"phalanx/v1": f.id},
            "properties": {
                "confidence": f.confidence,
                "status": f.status.value,
                "source": f.source,
            },
        })

    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Phalanx",
                    "version": tool_version,
                    "informationUri": "https://github.com/HarshJangra816/Phalanx",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }
