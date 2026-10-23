from pathlib import Path

import pytest

from phalanx.agent.budget import TokenBudget, Usage
from phalanx.findings import VulnClass
from phalanx.scanner.bench import ExpectedSet, evaluate, format_table, relative_to_root
from phalanx.scanner.pipeline import run_find
from phalanx.scanner.semgrep import semgrep_available

ROOT = Path(__file__).resolve().parents[1]
CHALLENGES = ROOT / "challenges"
LAB_FILE = ROOT / "lab" / "public" / "index.php"

AVAILABLE, _REASON = semgrep_available()
needs_semgrep = pytest.mark.skipif(not AVAILABLE, reason=f"semgrep: {_REASON}")


# ---------------------------------------------------------------- pipeline


@needs_semgrep
def test_run_find_on_lab():
    result = run_find(LAB_FILE, use_llm=False)
    assert result.ok, result.error
    classes = {f.vuln_class for f in result.findings}
    assert {VulnClass.XSS, VulnClass.CMDI, VulnClass.UPLOAD, VulnClass.LFI} <= classes
    assert result.tokens.total == 0


@needs_semgrep
def test_run_find_attaches_slices():
    result = run_find(LAB_FILE, use_llm=False)
    assert result.slices
    f = next(x for x in result.findings if x.vuln_class == VulnClass.CMDI)
    assert f.evidence["function"] == "ping_host"
    assert f.evidence["slice"] == [17, 20]


@needs_semgrep
def test_llm_skipped_without_key():
    result = run_find(LAB_FILE, client=None, budget=TokenBudget(1000),
                      use_llm=True)
    assert result.ok
    assert result.llm_enabled is False
    assert result.findings                  # deterministic still delivered


@needs_semgrep
def test_mock_provider_is_not_used_for_review():
    from phalanx.agent.router import MockClient

    result = run_find(LAB_FILE, client=MockClient(), budget=TokenBudget(10_000),
                      use_llm=True)
    assert result.llm_enabled is False
    assert any("mock" in e for e in result.llm_errors) or result.findings


@needs_semgrep
def test_budget_exhaustion_degrades_gracefully():
    from phalanx.agent.router import MockClient

    budget = TokenBudget(1)   # already below any call
    budget.charge(Usage(1, 0))
    result = run_find(CHALLENGES, client=MockClient(), budget=budget,
                      use_llm=True)
    assert result.ok
    assert result.findings                  # deterministic results survive
    assert any("budget" in e for e in result.llm_errors)


# ---------------------------------------------------------------- benchmark


@needs_semgrep
def test_challenge_set_scores_perfect_deterministic():
    """Phase 1 exit test: flags all vulns in the challenge set."""
    expected = ExpectedSet.load(CHALLENGES)
    assert len(expected.vulnerabilities) == 10
    result = run_find(CHALLENGES, use_llm=False)
    m = evaluate(relative_to_root(result.findings, CHALLENGES), expected,
                 CHALLENGES)
    assert m.fn == 0, f"missed vulns: {m.fn}"
    assert m.fp == 0, f"false positives: {m.fp}"
    assert m.precision == 1.0
    assert m.recall == 1.0


def test_evaluate_math_precision_recall(tmp_path):
    from phalanx.findings import Finding

    exp = ExpectedSet(vulnerabilities=[
        {"file": "a.php", "class": "sqli", "line": 5},
        {"file": "b.php", "class": "xss", "line": 10},
    ], clean_files=[])
    findings = [
        Finding(file=str(tmp_path / "a.php"), start_line=6, end_line=6,
                vuln_class=VulnClass.SQLI),
        Finding(file=str(tmp_path / "c.php"), start_line=1, end_line=1,
                vuln_class=VulnClass.CMDI),  # FP (unlabeled file)
    ]
    m = evaluate(findings, exp, tmp_path)
    assert (m.tp, m.fp, m.fn) == (1, 1, 1)
    assert m.precision == 0.5
    assert m.recall == 0.5


def test_evaluate_line_tolerance(tmp_path):
    from phalanx.findings import Finding

    exp = ExpectedSet(vulnerabilities=[{"file": "a.php", "class": "sqli", "line": 50}])
    near = Finding(file=str(tmp_path / "a.php"), start_line=54, end_line=54,
                   vuln_class=VulnClass.SQLI)
    assert evaluate([near], exp, tmp_path).tp == 1
    far = Finding(file=str(tmp_path / "a.php"), start_line=90, end_line=90,
                  vuln_class=VulnClass.SQLI)
    assert evaluate([far], exp, tmp_path).fn == 1


def test_format_table_renders():
    from phalanx.scanner.bench import Metrics

    text = format_table([("semgrep-only (baseline)", Metrics(tp=8, fp=4, fn=2))])
    assert "semgrep-only (baseline)" in text
    assert "66.7%" in text          # precision 8/(8+4)
    assert "80.0%" in text          # recall 8/(8+2)


def test_expected_set_requires_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        ExpectedSet.load(tmp_path)
