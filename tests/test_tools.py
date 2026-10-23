import json

import pytest

from phalanx.agent.tools import ToolContext, ToolRegistry, resolve_confined
from phalanx.config import PhalanxConfig


@pytest.fixture
def project(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.php").write_text(
        "<?php\nfunction greet() {\n    echo $_GET['name'];\n}\n",
        encoding="utf-8",
    )
    return tmp_path


def make_registry(project, allow_edit=False, runner=None):
    ctx = ToolContext(root=project, config=PhalanxConfig(), allow_edit=allow_edit,
                      runner=runner)
    return ToolRegistry(ctx)


def test_schemas_expose_fixed_surface(tmp_path):
    reg = make_registry(tmp_path)
    names = {t["name"] for t in reg.schemas()}
    assert names == {"read_file", "edit_file", "run_scan", "run_exploit", "run_tests"}


def test_read_file_numbers_lines(project):
    reg = make_registry(project)
    out = reg.dispatch("read_file", {"path": "src/app.php"})
    assert "1| <?php" in out
    assert "function greet()" in out


def test_read_file_rejects_traversal(project):
    reg = make_registry(project)
    out = reg.dispatch("read_file", {"path": "../outside.txt"})
    assert out.startswith("error:")


def test_read_file_rejects_absolute(project):
    reg = make_registry(project)
    out = reg.dispatch("read_file", {"path": "C:\\Windows\\win.ini"})
    assert out.startswith("error:")


def test_resolve_confined_ok(project):
    p = resolve_confined(project, "src/app.php")
    assert p.name == "app.php"


def test_edit_file_requires_fix_mode(project):
    reg = make_registry(project, allow_edit=False)
    out = reg.dispatch("edit_file", {"path": "src/app.php", "old": "echo", "new": "print"})
    assert "fix mode is not enabled" in out


def test_edit_file_applies(project):
    reg = make_registry(project, allow_edit=True)
    out = reg.dispatch("edit_file", {"path": "src/app.php",
                                     "old": "echo $_GET['name'];",
                                     "new": "echo htmlspecialchars($_GET['name'], ENT_QUOTES);"})
    assert out.startswith("ok:")
    assert "htmlspecialchars" in (project / "src" / "app.php").read_text(encoding="utf-8")


def test_edit_file_ambiguous_match_rejected(project):
    (project / "dup.php").write_text("x = 1\nx = 1\n", encoding="utf-8")
    reg = make_registry(project, allow_edit=True)
    out = reg.dispatch("edit_file", {"path": "dup.php", "old": "x = 1", "new": "x = 2"})
    assert "matches 2 times" in out


def test_run_exploit_requires_sandbox(project):
    reg = make_registry(project, runner=None)
    out = reg.dispatch("run_exploit", {"script": "<?php echo 1;"})
    assert "no sandbox" in out


def test_run_exploit_never_runs_on_host(project):
    # even with a malicious script, without a sandbox it must refuse
    reg = make_registry(project)
    out = reg.dispatch("run_exploit", {"script": "<?php system('rm -rf /');"})
    assert out.startswith("error:")


def test_run_scan_handles_missing_semgrep(project, tmp_path):
    reg = make_registry(project)
    out = reg.dispatch("run_scan", {})
    payload = json.loads(out)
    assert "findings" in payload  # structured even on error
