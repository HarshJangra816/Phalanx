import json
from pathlib import Path

from phalanx.findings import Finding, FindingStatus, VulnClass
from phalanx.output.sarif import SCHEMA, to_sarif


def sample_findings():
    return [
        Finding(file="lab/index.php", start_line=7, end_line=9,
                vuln_class=VulnClass.SQLI, confidence=0.7,
                message="SQLi via concat"),
        Finding(file="lab/index.php", start_line=13, end_line=13,
                vuln_class=VulnClass.XSS, confidence=0.9,
                status=FindingStatus.CONFIRMED, message="XSS confirmed"),
    ]


def test_sarif_top_level_shape():
    doc = to_sarif(sample_findings(), tool_version="0.1.0")
    assert doc["version"] == "2.1.0"
    assert doc["$schema"] == SCHEMA
    assert len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Phalanx"
    assert run["tool"]["driver"]["version"] == "0.1.0"


def test_sarif_is_serializable():
    json.dumps(to_sarif(sample_findings()))  # must not raise


def test_rules_match_findings():
    doc = to_sarif(sample_findings())
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    ids = [r["id"] for r in rules]
    assert ids == ["phalanx.php.sqli", "phalanx.php.xss"]
    assert all(r["helpUri"].startswith("https://cwe.mitre.org") for r in rules)


def test_results_and_levels():
    doc = to_sarif(sample_findings())
    results = doc["runs"][0]["results"]
    assert len(results) == 2
    levels = [r["level"] for r in results]
    assert levels == ["warning", "error"]     # hypothesis vs confirmed
    rid = results[0]["ruleId"]
    assert rid == "phalanx.php.sqli"
    rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert rid in rule_ids


def test_regions_and_uri():
    doc = to_sarif(sample_findings(), root=Path("lab"))
    loc = doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "index.php"
    region = loc["region"]
    assert region["startLine"] == 7
    assert region["endLine"] == 9


def test_single_line_has_no_end_line():
    doc = to_sarif(sample_findings(), root=Path("lab"))
    region = doc["runs"][0]["results"][1]["locations"][0]["physicalLocation"]["region"]
    assert "endLine" not in region


def test_empty_findings_still_valid():
    doc = to_sarif([])
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []
