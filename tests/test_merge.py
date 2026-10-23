from phalanx.findings import Finding, FindingStatus, VulnClass
from phalanx.scanner.merge import dedup_deterministic, merge_findings


def make(file="a.php", start=10, end=12, cls=VulnClass.SQLI, conf=0.7,
         source="semgrep", msg="", tokens=0):
    return Finding(file=file, start_line=start, end_line=end, vuln_class=cls,
                   confidence=conf, source=source, message=msg, tokens_used=tokens)


def test_dedup_collapses_overlapping_same_class():
    a = make(msg="rule one")
    b = make(start=11, msg="rule two")
    out = dedup_deterministic([a, b])
    assert len(out) == 1
    assert out[0].confidence == 0.7


def test_dedup_keeps_different_classes():
    a = make(cls=VulnClass.SQLI)
    b = make(cls=VulnClass.XSS)
    assert len(dedup_deterministic([a, b])) == 2


def test_dedup_keeps_distant_lines_same_file():
    a = make(start=1, end=3)
    b = make(start=50, end=52)
    assert len(dedup_deterministic([a, b])) == 2


def test_llm_finding_merges_into_deterministic():
    det = make(conf=0.7, msg="sqli via concat")
    llm = make(start=11, conf=0.9, source="llm", msg="likely FP: value is cast to int",
               tokens=500)
    out = merge_findings([det], [llm])
    assert len(out) == 1
    f = out[0]
    assert f.confidence == 0.9              # max wins
    assert f.source == "llm+semgrep"        # union
    assert f.tokens_used == 500
    assert "likely FP" in f.evidence["llm_reason"]


def test_unmatched_llm_finding_survives():
    det = make(file="a.php", start=1, end=2)
    llm = make(file="b.php", start=40, end=41, source="llm", cls=VulnClass.LOGIC,
               conf=0.6)
    out = merge_findings([det], [llm])
    assert len(out) == 2
    statuses = {f.status for f in out}
    assert statuses == {FindingStatus.HYPOTHESIS}


def test_unknown_class_merges_with_known():
    det = make(cls=VulnClass.UNKNOWN, conf=0.5)
    llm = make(cls=VulnClass.CMDI, conf=0.8, source="llm")
    out = merge_findings([det], [llm])
    assert len(out) == 1
    assert out[0].confidence == 0.8


def test_merge_result_sorted_by_file_and_line():
    a = make(file="z.php", start=5, end=6)
    b = make(file="a.php", start=30, end=31)
    out = merge_findings([a, b], [])
    assert [f.file for f in out] == ["a.php", "z.php"]
