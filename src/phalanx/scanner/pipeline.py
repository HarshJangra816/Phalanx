"""FIND stage pipeline: Semgrep -> slices -> (optional) LLM review -> merge."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from phalanx.agent.budget import BudgetExceeded, TokenBudget, Usage
from phalanx.findings import Finding
from phalanx.scanner.llm_review import review_slice
from phalanx.scanner.merge import dedup_deterministic, merge_findings
from phalanx.scanner.semgrep import ScanResult, run_semgrep
from phalanx.scanner.slicer import CodeSlice, slice_for_lines


@dataclass
class FindResult:
    findings: list[Finding] = field(default_factory=list)
    scan: ScanResult = field(default_factory=ScanResult)
    slices: list[CodeSlice] = field(default_factory=list)
    llm_enabled: bool = False
    llm_findings: int = 0
    llm_errors: list[str] = field(default_factory=list)
    tokens: Usage = field(default_factory=Usage)
    duration_ms: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


def _slice_findings(findings: list[Finding]) -> dict[str, CodeSlice]:
    """Attach a function-level slice to every finding (keyed by finding id)."""
    slices: dict[str, CodeSlice] = {}
    cache: dict[tuple[str, int], CodeSlice] = {}
    for f in findings:
        key = (f.file, f.start_line)
        if key not in cache:
            try:
                cache[key] = slice_for_lines(f.file, f.start_line, f.end_line)
            except OSError as exc:
                f.evidence["slice_error"] = str(exc)
                continue
        sl = cache[key]
        slices[f.id] = sl
        f.evidence["function"] = sl.name
        f.evidence["slice"] = [sl.start_line, sl.end_line]
    return slices


def run_find(target: str | Path, *, client=None, budget: TokenBudget | None = None,
             audit=None, use_llm: bool = True, rules_dir: Path | None = None,
             llm_max_slices: int = 20) -> FindResult:
    """Deterministic scan first; LLM only ever sees individual slices.

    Budget exhaustion or LLM errors degrade gracefully: deterministic
    findings are always returned.
    """
    started = time.monotonic()
    result = FindResult()
    target_path = Path(target)

    scan = run_semgrep(target_path, rules_dir=rules_dir)
    result.scan = scan
    if not scan.ok:
        result.error = scan.error
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    deterministic = dedup_deterministic(scan.findings)
    slices = _slice_findings(deterministic)
    result.slices = sorted({s.file + str(s.start_line): s for s in slices.values()}
                           .values(), key=lambda s: (s.file, s.start_line))

    llm_findings: list[Finding] = []
    skip_reason = ""
    if use_llm:
        if budget is None:
            skip_reason = "no token budget"
        else:
            try:
                budget.check()
            except BudgetExceeded as exc:
                skip_reason = f"budget exhausted: {exc}"
        if not skip_reason:
            if client is None:
                skip_reason = "no LLM client"
            elif getattr(client, "name", "") == "mock":
                skip_reason = "offline mock provider (no API key)"

    if use_llm and not skip_reason:
        result.llm_enabled = True
        # Review unique slices (hints = findings inside that slice)
        for reviewed, sl in enumerate(result.slices):
            if reviewed >= llm_max_slices:
                result.llm_errors.append(f"stopped at llm_max_slices={llm_max_slices}")
                break
            hints = [f for f in deterministic if f.id in slices
                     and slices[f.id] is sl]
            try:
                outcome = review_slice(client, budget, sl, hints=hints, audit=audit)
            except BudgetExceeded as exc:
                result.llm_errors.append(f"budget exhausted: {exc}")
                break
            except Exception as exc:  # noqa: BLE001 - LLM never kills FIND
                result.llm_errors.append(f"{type(exc).__name__}: {exc}")
                _log(audit, "llm_review_error", file=sl.file, error=str(exc))
                break
            result.tokens = result.tokens.add(outcome.usage)
            if outcome.error:
                result.llm_errors.append(f"{sl.file}:{sl.start_line} {outcome.error}")
            llm_findings.extend(outcome.findings)
    elif skip_reason:
        result.llm_errors.append(f"skipped: {skip_reason}")
        _log(audit, "llm_skipped", reason=skip_reason)

    result.llm_findings = len(llm_findings)
    result.findings = merge_findings(deterministic, llm_findings)
    result.duration_ms = int((time.monotonic() - started) * 1000)
    _log(audit, "find_end", findings=len(result.findings),
         deterministic=len(deterministic), llm=len(llm_findings),
         duration_ms=result.duration_ms)
    return result


def _log(audit, event: str, **data) -> None:
    fn = getattr(audit, "log", None)
    if callable(fn):
        fn(event, **data)
