"""Ephemeral Docker sandbox (ARCHITECTURE.md §3.3, §7).

Invariants:
  1. No outbound network (network_mode="none")
  2. Ephemeral container per run; destroyed after; no persistent state
  3. CPU / memory / wall-clock limits enforced
  4. Only canary/marker data is ever touched
  5. Every execution is audited

The Docker SDK is imported lazily so the rest of Phalanx works without it.
"""

from __future__ import annotations

import io
import logging
import tarfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from phalanx.config import SandboxConfig

log = logging.getLogger(__name__)

_EXCLUDE_DIRS = {".git", ".phalanx", "__pycache__", "node_modules",
                 ".venv", "venv", ".pytest_cache"}
_EXCLUDE_SUFFIXES = {".pyc", ".jsonl"}


class SandboxError(RuntimeError):
    """Raised when the sandbox cannot be created or an execution fails."""


class SandboxUnavailable(SandboxError):
    """Raised when Docker is not installed or the daemon is not reachable."""


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def docker_available() -> tuple[bool, str]:
    """Return (available, reason). Checks SDK import + daemon ping."""
    try:
        import docker  # noqa: PLC0415 - lazy optional dependency
    except ImportError:
        return False, "docker SDK not installed (pip install 'phalanx[sandbox]')"
    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:  # noqa: BLE001 - any daemon error means unavailable
        return False, f"Docker daemon not reachable: {exc}"
    return True, "ok"


def _should_exclude(path: Path) -> bool:
    if path.name in _EXCLUDE_DIRS:
        return True
    return path.suffix in _EXCLUDE_SUFFIXES


def build_project_tar(project: Path) -> bytes:
    """Tar the project directory (excluding VCS/runtime junk) for put_archive."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in sorted(project.rglob("*")):
            if any(_should_exclude(parent) for parent in path.parents):
                continue
            if _should_exclude(path) or not path.is_file():
                continue
            arcname = path.relative_to(project).as_posix()
            tar.add(path, arcname=arcname)
    return buf.getvalue()


class DockerSandbox:
    """Create -> run -> destroy lifecycle for one isolated PHP container."""

    def __init__(self, config: SandboxConfig, audit: object | None = None) -> None:
        self.config = config
        self._audit = audit
        self._client = None
        self._container = None
        self._project: Path | None = None
        self._log = ""

    # -- lifecycle ---------------------------------------------------------

    @property
    def container_id(self) -> str | None:
        return getattr(self._container, "id", None)

    @property
    def started(self) -> bool:
        return self._container is not None

    def start(self, project: Path) -> None:
        """Create the container, copy the project in, keep it alive."""
        if self._container is not None:
            raise SandboxError("sandbox already started")
        try:
            import docker  # noqa: PLC0415
        except ImportError as exc:
            raise SandboxUnavailable(
                "docker SDK not installed — pip install 'phalanx[sandbox]'") from exc

        self._client = docker.from_env()
        try:
            self._client.ping()
        except Exception as exc:  # noqa: BLE001
            raise SandboxUnavailable(f"Docker daemon not reachable: {exc}") from exc

        image = self.config.image
        try:
            self._client.images.get(image)
        except Exception:  # noqa: BLE001 - image missing locally
            log.info("pulling sandbox image %s", image)
            try:
                self._client.images.pull(image)
            except Exception as exc:  # noqa: BLE001
                raise SandboxError(f"cannot pull image {image!r}: {exc}") from exc

        name = f"phalanx-{uuid.uuid4().hex[:10]}"
        audit_log = getattr(self._audit, "log", None)
        if callable(audit_log):
            audit_log("sandbox_create", container=name, image=image,
                      network="none", memory=self.config.memory, cpus=self.config.cpus)

        try:
            self._container = self._client.containers.run(
                image,
                command=["sleep", "86400"],
                name=name,
                detach=True,
                network_mode="none",               # INVARIANT 1: no outbound network
                mem_limit=self.config.memory,      # INVARIANT 3: memory cap
                nano_cpus=int(self.config.cpus * 1e9),  # INVARIANT 3: cpu cap
                cap_drop=["ALL"],                  # hardening
                security_opt=["no-new-privileges:true"],
                labels={"phalanx": "sandbox", "run_id": name},
            )
        except Exception as exc:  # noqa: BLE001
            raise SandboxError(f"failed to start container: {exc}") from exc

        self._project = project
        self._copy_project(project)
        if callable(audit_log):
            audit_log("sandbox_started", container=name, id=self.container_id)

    def _copy_project(self, project: Path) -> None:
        """Copy project files into the container via put_archive (no host mounts)."""
        assert self._container is not None
        self._ensure_workdir()
        tar_bytes = build_project_tar(project)
        ok = self._container.put_archive(self.config.workdir, tar_bytes)
        if not ok:
            raise SandboxError("put_archive failed copying project into sandbox")

    def _ensure_workdir(self) -> None:
        assert self._container is not None
        code, _ = self._container.exec_run(
            ["sh", "-c", f"mkdir -p {self.config.workdir}"])
        if code != 0:
            raise SandboxError(f"cannot create workdir {self.config.workdir}")

    # -- execution ---------------------------------------------------------

    def exec(self, argv: list[str], timeout: int | None = None,
             workdir: str | None = None) -> ExecResult:
        """Run a command in the container with a wall-clock timeout."""
        if self._container is None:
            raise SandboxError("sandbox not started")
        timeout = timeout or self.config.timeout_seconds
        # in-container timeout (busybox) as the primary guard
        guarded = ["timeout", "-s", "KILL", str(timeout), *argv]
        cwd = workdir or self.config.workdir
        start = time.monotonic()
        try:
            exit_code, output = self._container.exec_run(
                guarded, workdir=cwd, stdout=True, stderr=True, demux=False)
        except Exception as exc:  # noqa: BLE001
            raise SandboxError(f"exec failed: {exc}") from exc
        text = output.decode("utf-8", errors="replace") if isinstance(output, bytes) \
            else (output or "")
        duration_ms = int((time.monotonic() - start) * 1000)
        # busybox timeout exits 137 (KILL) or 124 on expiry
        timed_out = exit_code in (124, 137)
        result = ExecResult(exit_code=exit_code, stdout=text, stderr="",
                            timed_out=timed_out, duration_ms=duration_ms)
        audit_log = getattr(self._audit, "log", None)
        if callable(audit_log):
            audit_log("sandbox_exec", argv=argv, exit_code=exit_code,
                      timed_out=timed_out, duration_ms=duration_ms,
                      output_bytes=len(text))
        return result

    def put_file(self, rel_path: str, content: str | bytes) -> str:
        """Write a file into the container workdir; returns absolute path."""
        if self._container is None:
            raise SandboxError("sandbox not started")
        data = content.encode("utf-8") if isinstance(content, str) else content
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name=Path(rel_path).name)
            info.size = len(data)
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(data))
        parent = (Path(self.config.workdir) / Path(rel_path).parent).as_posix()
        self._ensure_dir(parent)
        self._container.put_archive(parent, buf.getvalue())
        return (Path(self.config.workdir) / rel_path).as_posix()

    def _ensure_dir(self, path: str) -> None:
        assert self._container is not None
        self._container.exec_run(["sh", "-c", f"mkdir -p {path}"])

    # -- teardown ----------------------------------------------------------

    def destroy(self) -> None:
        """Remove the container unconditionally (ephemeral by design)."""
        if self._container is None:
            return
        audit_log = getattr(self._audit, "log", None)
        try:
            self._container.remove(force=True)
            if callable(audit_log):
                audit_log("sandbox_destroyed", container=self._container.name)
        except Exception as exc:  # noqa: BLE001 - never mask the real error
            log.warning("sandbox cleanup failed: %s", exc)
            if callable(audit_log):
                audit_log("sandbox_destroy_failed", error=str(exc))
        finally:
            self._container = None

    def __enter__(self) -> DockerSandbox:
        return self

    def __exit__(self, *exc: object) -> None:
        self.destroy()
