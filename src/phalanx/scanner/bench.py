"""Benchmark: run the FIND pipeline against a challenge set with known
ground truth (`expected.json`) — Phalanx vs Semgrep-only baseline.

Expected file format (challenges/expected.json):
{
  "vulnerabilities": [{"file": "sqli/easy.php", "class": "sqli", "line": 7}],
  "clean_files": ["sqli/clean.php"]
}
A finding is a true positive if file matches, class matches, and (when a
line is given) the finding's range is within ±5 lines. Findings on clean
files, or of an unlabeled class in a labeled file, are false positives.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from phalanx.findings import Finding
from phalanx.scanner.pipeline import FindResult

LINE_TOLERANCE = 5


@dataclass
class ExpectedSet:
    vulnerabilities: list[dict] = field(default_factory=list)
    clean_files: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, directory: str | Path) -> ExpectedSet:
        path = Path(directory) / "expected.json"
        if not path.exists():
            raise FileNotFoundError(f"no expected.json in {directory}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(vulnerabilities=data.get("vulnerabilities", []),
                   clean_files=data.get("clean_files", []))


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    def to_dict(self) -> dict:
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn,
                "precision": round(self.precision, 3),
                "recall": round(self.recall, 3)}


def _rel(file: str, root: Path) -> str:
    try:
        return Path(file).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return Path(file).as_posix()


def evaluate(findings: list[Finding], expected: ExpectedSet, root: Path) -> Metrics:
    """Score findings against ground truth."""
    m = Metrics()
    matched: set[int] = set()  # ids of findings that were true positives

    for vuln in expected.vulnerabilities:
        want_file = Path(vuln["file"]).as_posix()
        want_class = vuln["class"]
        want_line = vuln.get("line")
        hit = None
        for f in findings:
            if f.id in matched:
                continue
            if _rel(f.file, root) != want_file:
                continue
            if f.vuln_class.value != want_class:
                continue
            if want_line is not None and not (
                want_line - LINE_TOLERANCE <= f.start_line
                <= want_line + LINE_TOLERANCE + (f.end_line - f.start_line)
            ):
                continue
            hit = f
            break
        if hit is not None:
            m.tp += 1
            matched.add(hit.id)
        else:
            m.fn += 1

    # anything unmatched = false positive
    for f in findings:
        if f.id not in matched:
            m.fp += 1
    return m


def relative_to_root(findings: list[Finding], root: Path) -> list[Finding]:
    """Keep only findings under root (bench target is the challenge dir)."""
    root_res = root.resolve()
    out = []
    for f in findings:
        p = Path(f.file).resolve()
        if p == root_res or root_res in p.parents:
            out.append(f)
    return out


def format_table(rows: list[tuple[str, Metrics]]) -> str:
    lines = [f"{'variant':<24} {'prec':>7} {'recall':>7} {'tp':>4} {'fp':>4} {'fn':>4}"]
    lines.append("-" * 54)
    for name, m in rows:
        lines.append(f"{name:<24} {m.precision:>6.1%} {m.recall:>6.1%} "
                     f"{m.tp:>4} {m.fp:>4} {m.fn:>4}")
    return "\n".join(lines)


def run_bench(challenges: Path, *, client=None, budget=None, audit=None,
              use_llm: bool = True) -> tuple[list[tuple[str, Metrics]], dict]:
    """Run baseline (semgrep-only) + full pipeline, return (table rows, raw)."""
    expected = ExpectedSet.load(challenges)

    baseline: FindResult = _scan(challenges, use_llm=False)
    full: FindResult = _scan(challenges, use_llm=use_llm, client=client,
                             budget=budget, audit=audit)

    m_base = evaluate(relative_to_root(baseline.findings, challenges),
                      expected, challenges)
    m_full = evaluate(relative_to_root(full.findings, challenges),
                      expected, challenges)

    rows = [("semgrep-only (baseline)", m_base),
            ("phalanx (find stage)", m_full)]
    raw = {
        "baseline": m_base.to_dict(),
        "phalanx": m_full.to_dict(),
        "llm_enabled": full.llm_enabled,
        "llm_errors": full.llm_errors,
        "expected": len(expected.vulnerabilities),
        "clean_files": len(expected.clean_files),
    }
    return rows, raw


def _scan(challenges: Path, *, use_llm: bool, client=None, budget=None,
          audit=None) -> FindResult:
    from phalanx.scanner.pipeline import run_find

    return run_find(challenges, client=client, budget=budget, audit=audit,
                    use_llm=use_llm)
