"""Fixed agent tool surface (ROADMAP Phase 0).

Tools: read_file, edit_file, run_scan, run_exploit, run_tests.
The agent never gets raw shell access — only these wrappers.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from phalanx.config import PhalanxConfig


class ToolError(Exception):
    """User-visible tool failure (fed back to the model as the tool result)."""


@dataclass
class ToolContext:
    """Everything the tool handlers may touch."""

    root: Path
    config: PhalanxConfig
    audit: Any = None
    allow_edit: bool = False
    runner: Any = None  # SandboxRunner, provided lazily by the CLI/agent
    budget: Any = None  # TokenBudget, used by run_scan accounting

    def log(self, event: str, **data: Any) -> None:
        fn = getattr(self.audit, "log", None)
        if callable(fn):
            fn(event, **data)


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], str]

    def to_schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description,
                "input_schema": self.input_schema}


def resolve_confined(root: Path, rel_path: str) -> Path:
    """Resolve rel_path inside root; reject traversal outside the project."""
    if Path(rel_path).is_absolute():
        raise ToolError(f"absolute paths are not allowed: {rel_path}")
    candidate = (root / rel_path).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        raise ToolError(f"path escapes project root: {rel_path}")
    return candidate


def format_numbered(text: str) -> str:
    lines = text.splitlines()
    width = max(3, len(str(len(lines))))
    return "\n".join(f"{i:>{width}}| {ln}" for i, ln in enumerate(lines, 1))


class ToolRegistry:
    """Builds the fixed tool surface over a ToolContext."""

    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx
        self._tools: dict[str, ToolSpec] = {}
        self._register_builtin()

    # -- registration ------------------------------------------------------

    def _register_builtin(self) -> None:
        self.register(ToolSpec(
            name="read_file",
            description=("Read a file from the project (or from inside the sandbox "
                         "when a sandbox runner is attached). Returns numbered lines."),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "path relative to project root"},
                    "via_sandbox": {"type": "boolean",
                                    "description": "read through the sandbox container"},
                },
                "required": ["path"],
            },
            handler=self.read_file,
        ))
        self.register(ToolSpec(
            name="edit_file",
            description=("Apply an exact-text replacement in a project file. "
                         "Requires fix mode. The old text must match exactly once."),
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "old": {"type": "string", "description": "exact text to replace"},
                    "new": {"type": "string", "description": "replacement text"},
                },
                "required": ["path", "old", "new"],
            },
            handler=self.edit_file,
        ))
        self.register(ToolSpec(
            name="run_scan",
            description=("Run deterministic static analysis (Semgrep) on the project "
                         "and return normalized findings as JSON."),
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string",
                               "description": "subdirectory or file to scan "
                                              "(default: whole project)"},
                },
                "required": [],
            },
            handler=self.run_scan,
        ))
        self.register(ToolSpec(
            name="run_exploit",
            description=("Execute a SAFE proof-of-concept PHP script inside the "
                         "sandbox. Read-a-canary class only (marker PHALANX_CANARY{...}). "
                         "Never destructive. Returns structured result."),
            input_schema={
                "type": "object",
                "properties": {
                    "script": {"type": "string", "description": "PHP source of the safe PoC"},
                },
                "required": ["script"],
            },
            handler=self.run_exploit,
        ))
        self.register(ToolSpec(
            name="run_tests",
            description=("Run the application's test suite (PHPUnit) inside the "
                         "sandbox. Returns pass/fail + failure lines."),
            input_schema={
                "type": "object",
                "properties": {
                    "command": {"type": "array", "items": {"type": "string"},
                                "description": "override test command "
                                               "(default: vendor/bin/phpunit)"},
                },
                "required": [],
            },
            handler=self.run_tests,
        ))

    def register(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def schemas(self) -> list[dict[str, Any]]:
        return [t.to_schema() for t in self._tools.values()]

    def dispatch(self, name: str, arguments: dict[str, Any]) -> str:
        """Run a tool by name; returns text result (errors returned as text)."""
        spec = self._tools.get(name)
        if spec is None:
            return f"error: unknown tool {name!r}"
        self.ctx.log("tool_call", tool=name, arguments=arguments)
        try:
            result = spec.handler(arguments or {})
        except ToolError as exc:
            self.ctx.log("tool_result", tool=name, status="error", error=str(exc))
            return f"error: {exc}"
        except Exception as exc:  # noqa: BLE001 - never crash the loop
            self.ctx.log("tool_result", tool=name, status="error", error=str(exc))
            return f"error: {type(exc).__name__}: {exc}"
        self.ctx.log("tool_result", tool=name, status="ok", bytes=len(result))
        return result

    # -- handlers ----------------------------------------------------------

    def read_file(self, args: dict[str, Any]) -> str:
        path = args.get("path")
        if not path:
            raise ToolError("read_file: 'path' is required")
        via_sandbox = bool(args.get("via_sandbox", False))
        if via_sandbox:
            runner = self.ctx.runner
            if runner is None:
                raise ToolError("read_file: no sandbox runner attached")
            try:
                content = runner.read_file(path)
            except FileNotFoundError as exc:
                raise ToolError(str(exc)) from exc
            return format_numbered(content)

        target = resolve_confined(self.ctx.root, path)
        if not target.exists():
            raise ToolError(f"file not found: {path}")
        if target.is_dir():
            raise ToolError(f"is a directory, not a file: {path}")
        try:
            content = target.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ToolError(f"cannot read {path}: {exc}") from exc
        return format_numbered(content)

    def edit_file(self, args: dict[str, Any]) -> str:
        if not self.ctx.allow_edit:
            raise ToolError("edit_file: fix mode is not enabled for this run")
        path = args.get("path")
        old = args.get("old")
        new = args.get("new")
        if not path or old is None or new is None:
            raise ToolError("edit_file: 'path', 'old', and 'new' are required")
        if old == new:
            raise ToolError("edit_file: 'old' and 'new' are identical")
        target = resolve_confined(self.ctx.root, path)
        if not target.exists():
            raise ToolError(f"file not found: {path}")
        content = target.read_text(encoding="utf-8")
        count = content.count(old)
        if count == 0:
            raise ToolError("edit_file: 'old' text not found in file")
        if count > 1:
            raise ToolError(f"edit_file: 'old' text matches {count} times; make it unique")
        before_hash = hash(content)
        target.write_text(content.replace(old, new, 1), encoding="utf-8")
        self.ctx.log("file_edited", path=path, old_bytes=len(old), new_bytes=len(new),
                     before_hash=before_hash)
        return f"ok: edited {path} ({len(old)} -> {len(new)} bytes)"

    def run_scan(self, args: dict[str, Any]) -> str:
        from phalanx.scanner.semgrep import run_semgrep  # local import avoids cycle

        target_arg = args.get("target") or "."
        target = resolve_confined(self.ctx.root, target_arg)
        if not target.exists():
            raise ToolError(f"scan target not found: {target_arg}")
        result = run_semgrep(target)
        payload = {
            "ok": result.ok,
            "error": result.error,
            "files_scanned": result.files_scanned,
            "findings": [
                {
                    "file": f.file,
                    "start_line": f.start_line,
                    "end_line": f.end_line,
                    "vuln_class": f.vuln_class.value,
                    "confidence": f.confidence,
                    "message": f.message,
                }
                for f in result.findings
            ],
        }
        return json.dumps(payload, indent=2)

    def run_exploit(self, args: dict[str, Any]) -> str:
        script = args.get("script")
        if not script:
            raise ToolError("run_exploit: 'script' is required")
        if self.ctx.runner is None:
            raise ToolError("run_exploit: no sandbox attached — exploits never run on the host")
        outcome = self.ctx.runner.run_exploit(script)
        return json.dumps(outcome.to_dict(), indent=2)

    def run_tests(self, args: dict[str, Any]) -> str:
        if self.ctx.runner is None:
            raise ToolError("run_tests: no sandbox attached")
        command = args.get("command")
        if command is not None and not isinstance(command, list):
            raise ToolError("run_tests: 'command' must be an array of strings")
        outcome = self.ctx.runner.run_tests(command)
        return json.dumps(outcome.to_dict(), indent=2)
