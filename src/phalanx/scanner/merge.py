"""Dedup/merge of deterministic (Semgrep) and LLM findings (Phase 1)."""

from __future__ import annotations

from phalanx.findings import Finding, VulnClass

LINE_TOLERANCE = 5


def _ranges_overlap(a: Finding, b: Finding, tol: int = LINE_TOLERANCE) -> bool:
    return not (a.end_line + tol < b.start_line or b.end_line + tol < a.start_line)


def _classes_compatible(a: Finding, b: Finding) -> bool:
    if a.vuln_class == b.vuln_class:
        return True
    return VulnClass.UNKNOWN in (a.vuln_class, b.vuln_class)


def _merge_pair(primary: Finding, other: Finding) -> Finding:
    """Merge `other` into `primary` (primary = deterministic, usually)."""
    primary.confidence = max(primary.confidence, other.confidence)
    sources = {s for s in (primary.source, other.source) if s}
    primary.source = "+".join(sorted(sources))
    primary.tokens_used += other.tokens_used
    if other.model and other.model not in primary.model:
        primary.model = f"{primary.model}+{other.model}".strip("+")
    if other.message and other.message != primary.message:
        primary.evidence.setdefault("llm_reason", other.message)
    if other.evidence:
        primary.evidence.setdefault("llm_evidence", other.evidence)
    primary.end_line = max(primary.end_line, other.end_line)
    primary.start_line = min(primary.start_line, other.start_line)
    return primary


def dedup_deterministic(findings: list[Finding]) -> list[Finding]:
    """Collapse same-file, same-class, overlapping deterministic findings
    (e.g. a line flagged by two rules of one class)."""
    kept: list[Finding] = []
    for f in sorted(findings, key=lambda x: (x.file, x.start_line, -x.confidence)):
        twin = next(
            (k for k in kept
             if k.file == f.file and k.vuln_class == f.vuln_class
             and _ranges_overlap(k, f)),
            None,
        )
        if twin is None:
            kept.append(f)
        else:
            _merge_pair(twin, f)
    return kept


def merge_findings(deterministic: list[Finding], llm: list[Finding]) -> list[Finding]:
    """Union of both sources: LLM findings attach to overlapping deterministic
    findings (raising confidence, adding reasoning); unmatched survive as
    HYPOTHESIS with their own confidence."""
    result = dedup_deterministic(deterministic)
    for lf in sorted(llm, key=lambda x: (x.file, x.start_line)):
        twin = next(
            (k for k in result
             if k.file == lf.file and _classes_compatible(k, lf)
             and _ranges_overlap(k, lf)),
            None,
        )
        if twin is None:
            result.append(lf)
        else:
            _merge_pair(twin, lf)
    result.sort(key=lambda x: (x.file, x.start_line))
    return result
