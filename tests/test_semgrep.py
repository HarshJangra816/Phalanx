"""Semgrep runner tests — scanning tests skip when semgrep is not installed."""

from pathlib import Path

import pytest

from phalanx.findings import VulnClass
from phalanx.scanner.semgrep import (
    _classify,
    run_semgrep,
    semgrep_available,
)

AVAILABLE, _REASON = semgrep_available()

VULN_PHP = """\
<?php
function get_user($db) {
    $name = $_GET['name'];
    $q = "SELECT * FROM users WHERE name = '" . $name . "'";
    return mysqli_query($db, $q);
}
"""


def test_classify_rule_ids():
    assert _classify("php.sqli.concat") == VulnClass.SQLI
    assert _classify("php.security.xss-echo") == VulnClass.XSS
    assert _classify("php.cmdi.system") == VulnClass.CMDI
    assert _classify("php.upload.no-validation") == VulnClass.UPLOAD
    assert _classify("php.lfi.include-get") == VulnClass.LFI
    assert _classify("weird.rule") == VulnClass.UNKNOWN


def test_missing_semgrep_returns_structured_error(tmp_path):
    result = run_semgrep(tmp_path, rules_dir=tmp_path)  # empty rules dir
    # either semgrep missing or no rules — must be structured, never a crash
    assert result.findings == []
    assert result.error


@pytest.mark.skipif(not AVAILABLE, reason="semgrep not installed")
def test_scan_flags_lab_vulns(tmp_path):
    (tmp_path / "app.php").write_text(VULN_PHP, encoding="utf-8")
    result = run_semgrep(tmp_path)
    assert result.ok, result.error
    assert any(f.vuln_class == VulnClass.SQLI for f in result.findings)


def test_runner_is_importable():
    assert callable(run_semgrep)
    assert callable(semgrep_available)


def test_rules_dir_has_readme():
    rules = Path(__file__).resolve().parents[1] / "rules"
    assert (rules / "README.md").exists()
