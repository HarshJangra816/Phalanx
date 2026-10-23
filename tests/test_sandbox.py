"""Sandbox tests — skipped entirely when Docker is unavailable.

These verify the sandbox invariants from ARCHITECTURE.md §7:
no outbound network, resource caps, ephemeral lifecycle.
"""

from pathlib import Path

import pytest

from phalanx.config import SandboxConfig
from phalanx.sandbox.docker_sandbox import (
    DockerSandbox,
    SandboxUnavailable,
    build_project_tar,
    docker_available,
)

AVAILABLE, REASON = docker_available()

pytestmark = pytest.mark.skipif(not AVAILABLE, reason=f"sandbox needs Docker: {REASON}")

CONFIG = SandboxConfig(timeout_seconds=30)


@pytest.fixture
def project(tmp_path):
    (tmp_path / "index.php").write_text("<?php echo 'PHALANX_CANARY{lab_test}';\n",
                                        encoding="utf-8")
    return tmp_path


def test_docker_available_reports_reason():
    ok, reason = docker_available()
    assert isinstance(ok, bool)
    assert reason


def test_build_project_tar_excludes_junk(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("x", encoding="utf-8")
    (tmp_path / "app.php").write_text("<?php", encoding="utf-8")
    import io
    import tarfile

    data = build_project_tar(tmp_path)
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        names = tar.getnames()
    assert "app.php" in names
    assert not any(n.startswith(".git") for n in names)


def test_lifecycle_and_read(project):
    sandbox = DockerSandbox(CONFIG)
    try:
        sandbox.start(project)
        assert sandbox.started
        # file copied into container, readable in-container
        from phalanx.sandbox.runners import SandboxRunner

        runner = SandboxRunner(sandbox, CONFIG)
        content = runner.read_file("index.php")
        assert "PHALANX_CANARY{lab_test}" in content
    finally:
        sandbox.destroy()
    assert not sandbox.started


def test_network_isolation_proven(project):
    sandbox = DockerSandbox(CONFIG)
    try:
        sandbox.start(project)
        from phalanx.sandbox.runners import SandboxRunner

        runner = SandboxRunner(sandbox, CONFIG)
        check = runner.verify_network_isolation()
        assert check.isolated, f"sandbox reached the network: {check.evidence}"
    finally:
        sandbox.destroy()


def test_exec_wall_clock_timeout(project):
    sandbox = DockerSandbox(CONFIG)
    try:
        sandbox.start(project)
        result = sandbox.exec(["php", "-r", "sleep(60);"], timeout=3)
        assert result.timed_out
    finally:
        sandbox.destroy()


def test_exploit_runs_only_in_container(project):
    sandbox = DockerSandbox(CONFIG)
    try:
        sandbox.start(project)
        from phalanx.sandbox.runners import SandboxRunner

        runner = SandboxRunner(sandbox, CONFIG)
        outcome = runner.run_exploit("<?php echo 'PHALANX_CANARY{abc}';")
        assert outcome.status == "executed"
        assert outcome.canary == "PHALANX_CANARY{abc}"
        assert outcome.succeeded
    finally:
        sandbox.destroy()


def test_start_without_docker_raises(project, monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "docker":
            raise ImportError("no docker")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(SandboxUnavailable):
        DockerSandbox(CONFIG).start(Path(project))
