"""Sandbox runners: run_exploit and run_tests — the only execution paths.

Safety rules (SAFETY.md):
  - Exploit scripts execute ONLY inside the container, never on the host.
  - PoCs are read-a-canary / extract-a-marker class. No destructive payloads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from phalanx.config import SandboxConfig
from phalanx.sandbox.docker_sandbox import DockerSandbox, ExecResult

# A successful exploit must exfiltrate a canary — proof of impact without real data.
CANARY_PATTERN = re.compile(r"PHALANX_CANARY\{[A-Za-z0-9_\-]+\}")


@dataclass
class ExploitResult:
    status: str  # executed | timeout | error | no_sandbox
    exit_code: int | None = None
    output: str = ""
    canary: str | None = None
    duration_ms: int = 0
    error: str = ""

    @property
    def succeeded(self) -> bool:
        """The exploit ran AND captured the canary => vulnerability is real."""
        return self.status == "executed" and self.canary is not None

    def to_dict(self) -> dict:
        return {
            "status": self.status, "exit_code": self.exit_code, "output": self.output,
            "canary": self.canary, "duration_ms": self.duration_ms, "error": self.error,
        }


@dataclass
class TestResult:
    status: str  # passed | failed | no_tests | error
    exit_code: int | None = None
    output: str = ""
    duration_ms: int = 0
    failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "status": self.status, "exit_code": self.exit_code, "output": self.output,
            "duration_ms": self.duration_ms, "failures": self.failures,
        }


@dataclass
class NetworkCheck:
    isolated: bool
    evidence: str

    def to_dict(self) -> dict:
        return {"isolated": self.isolated, "evidence": self.evidence}


class SandboxRunner:
    """High-level sandbox operations used by the agent tools."""

    def __init__(self, sandbox: DockerSandbox, config: SandboxConfig,
                 audit: object | None = None) -> None:
        self.sandbox = sandbox
        self.config = config
        self._audit = audit

    def _audit_log(self, event: str, **data) -> None:
        fn = getattr(self._audit, "log", None)
        if callable(fn):
            fn(event, **data)

    # -- read --------------------------------------------------------------

    def read_file(self, rel_path: str) -> str:
        """Read a file from inside the container (proves sandbox file access)."""
        result = self.sandbox.exec(["cat", rel_path])
        if not result.ok:
            raise FileNotFoundError(
                f"cannot read {rel_path} in sandbox (exit {result.exit_code})")
        return result.stdout

    # -- exploit -----------------------------------------------------------

    def run_exploit(self, script: str, timeout: int | None = None) -> ExploitResult:
        """Execute an agent-authored safe PoC INSIDE the container.

        The script is written to /tmp inside the container and run with php.
        A successful exploit is one that captures the PHALANX_CANARY{...} marker.
        """
        self._audit_log("exploit_attempt", script_bytes=len(script),
                        target="sandbox", sandbox_id=self.sandbox.container_id)
        try:
            path = self.sandbox.put_file(f"../tmp/phalanx_poc_{id(script) % 10_000}.php",
                                          script)
            result: ExecResult = self.sandbox.exec(["php", path],
                                                   timeout=timeout or self.config.timeout_seconds)
        except Exception as exc:  # noqa: BLE001 - surface as structured result
            self._audit_log("exploit_result", status="error", error=str(exc))
            return ExploitResult(status="error", error=str(exc))

        canary = CANARY_PATTERN.search(result.stdout)
        status = "timeout" if result.timed_out else "executed"
        outcome = ExploitResult(
            status=status, exit_code=result.exit_code, output=result.stdout[-8000:],
            canary=canary.group(0) if canary else None, duration_ms=result.duration_ms,
        )
        self._audit_log("exploit_result", status=outcome.status,
                        canary_found=outcome.canary is not None,
                        exit_code=outcome.exit_code)
        return outcome

    # -- tests -------------------------------------------------------------

    def run_tests(self, command: list[str] | None = None) -> TestResult:
        """Run the app's PHPUnit suite inside the container (regression gate)."""
        argv = command or ["vendor/bin/phpunit", "--testdox"]
        result = self.sandbox.exec(argv, timeout=self.config.timeout_seconds * 5)
        output = result.stdout
        if "not found" in output.lower() or "no such file" in output.lower():
            self._audit_log("tests_result", status="no_tests")
            return TestResult(status="no_tests", exit_code=result.exit_code,
                              output=output[-4000:], duration_ms=result.duration_ms)
        failures = [ln for ln in output.splitlines()
                    if re.search(r"\b(Failures?:|Errors?:|FAILED|✘)\b", ln)]
        status = "passed" if result.ok else "failed"
        self._audit_log("tests_result", status=status, failures=len(failures))
        return TestResult(status=status, exit_code=result.exit_code,
                          output=output[-8000:], duration_ms=result.duration_ms,
                          failures=failures[:50])

    # -- network isolation proof -------------------------------------------

    def verify_network_isolation(self) -> NetworkCheck:
        """Empirically prove the container has no outbound network.

        Tries HTTP and DNS from inside. Both must fail for the sandbox to be
        considered isolated (invariant 1).
        """
        probe = (
            "$ok=0;"
            "$r=@file_get_contents('http://1.1.1.1', false, "
            "stream_context_create(['http'=>['timeout'=>3]]));"
            "if($r!==false){$ok=1;}"
            "$d=@gethostbyname('example.com');"
            "if($d!=='example.com'){$ok=1;}"
            "echo $ok===0?'ISOLATED':'REACHABLE';"
        )
        result = self.sandbox.exec(["php", "-r", probe], timeout=30)
        isolated = "ISOLATED" in result.stdout and "REACHABLE" not in result.stdout
        evidence = (result.stdout.strip() or f"exit={result.exit_code} (php probe failed)")
        self._audit_log("network_check", isolated=isolated, evidence=evidence)
        return NetworkCheck(isolated=isolated, evidence=evidence)


def build_runner(project: Path, config: SandboxConfig, audit: object | None = None
                 ) -> tuple[DockerSandbox, SandboxRunner]:
    """Convenience: start a sandbox on `project` and return (sandbox, runner)."""
    sandbox = DockerSandbox(config, audit=audit)
    sandbox.start(project)
    return sandbox, SandboxRunner(sandbox, config, audit=audit)
