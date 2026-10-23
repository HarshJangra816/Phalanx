"""Phalanx CLI — argparse-based, stdlib-only.

Commands:
  phalanx ask <file> <question>   agent answers questions about a PHP file
  phalanx scan <path>             deterministic scan (Semgrep) -> findings
  phalanx fix <path>              generate + verify fixes (Phase 3)
  phalanx sandbox check           prove sandbox network isolation
  phalanx doctor                  environment report
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from phalanx import __version__
from phalanx.agent.audit import AuditLogger
from phalanx.agent.budget import TokenBudget
from phalanx.agent.loop import AgentLoop
from phalanx.agent.router import build_client
from phalanx.agent.tools import ToolContext, ToolRegistry
from phalanx.config import PhalanxConfig, load_config
from phalanx.output.terminal import (
    render_answer,
    render_findings,
    render_network_check,
)
from phalanx.sandbox.docker_sandbox import docker_available
from phalanx.scanner.semgrep import semgrep_available


def _warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


def _load(args: argparse.Namespace) -> PhalanxConfig:
    cfg = load_config(getattr(args, "config", None))
    # CLI overrides
    from dataclasses import replace

    llm = cfg.llm
    if getattr(args, "provider", None):
        llm = replace(llm, provider=args.provider.lower())
    budget = cfg.budget
    if getattr(args, "budget", None):
        budget = replace(budget, max_tokens=args.budget)
    return replace(cfg, llm=llm, budget=budget)


def _attach_sandbox(cfg: PhalanxConfig, project: Path, audit: AuditLogger,
                    force: bool = False):
    """Start a sandbox + runner if possible. Returns (sandbox, runner) or (None, None)."""
    if not force and not cfg.sandbox.enabled:
        return None, None
    ok, reason = docker_available()
    if not ok:
        _warn(f"sandbox unavailable ({reason}); sandboxed tools will be disabled")
        return None, None
    from phalanx.sandbox.docker_sandbox import DockerSandbox
    from phalanx.sandbox.runners import SandboxRunner

    sandbox = DockerSandbox(cfg.sandbox, audit=audit)
    try:
        sandbox.start(project)
    except Exception as exc:  # noqa: BLE001
        _warn(f"sandbox start failed: {exc}")
        return None, None
    return sandbox, SandboxRunner(sandbox, cfg.sandbox, audit=audit)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_ask(args: argparse.Namespace) -> int:
    cfg = _load(args)
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"error: file not found: {file_path}", file=sys.stderr)
        return 2

    project = file_path.parent.resolve()
    rel = file_path.name

    with AuditLogger(cfg.audit_dir) as audit:
        budget = TokenBudget(cfg.budget.max_tokens)
        client = build_client(cfg.llm, warn=_warn)

        sandbox = runner = None
        if not args.no_sandbox:
            sandbox, runner = _attach_sandbox(cfg, project, audit)

        ctx = ToolContext(root=project, config=cfg, audit=audit,
                          allow_edit=False, runner=runner, budget=budget)
        registry = ToolRegistry(ctx)
        loop = AgentLoop(client, registry, budget, audit=audit)

        system_extra = f"Target file: {rel}\nProject root: {project}"
        if runner is not None:
            system_extra += "\nSandbox: attached (use via_sandbox=true to read in-container)"
        try:
            result = loop.run(args.question, system_extra=system_extra)
        finally:
            if sandbox is not None:
                sandbox.destroy()

    print(render_answer(result.answer, result.stopped, result.usage.total, result.model))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    cfg = _load(args)
    target = Path(args.path).resolve()
    if not target.exists():
        print(f"error: path not found: {target}", file=sys.stderr)
        return 2

    from phalanx.scanner.pipeline import run_find

    with AuditLogger(cfg.audit_dir) as audit:
        budget = TokenBudget(cfg.budget.max_tokens)
        client = build_client(cfg.llm, stage="triage", warn=_warn)
        audit.log("scan_start", target=str(target), format=args.format,
                  llm=not args.no_llm)
        result = run_find(target, client=client, budget=budget, audit=audit,
                          use_llm=not args.no_llm)

    if not result.ok:
        print(f"error: {result.error}", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps({
            "findings": [f.to_dict() for f in result.findings],
            "summary": {
                "count": len(result.findings),
                "files_scanned": result.scan.files_scanned,
                "llm_enabled": result.llm_enabled,
                "tokens": result.tokens.total,
                "duration_ms": result.duration_ms,
                "llm_errors": result.llm_errors,
            },
        }, indent=2))
    elif args.format == "sarif":
        from phalanx.output.sarif import to_sarif

        print(json.dumps(to_sarif(result.findings, tool_version=__version__,
                                  root=target if target.is_dir() else target.parent),
                         indent=2))
    else:
        print(render_findings(result.findings))
        llm_note = (f" · llm: {result.llm_findings} hypothesis(es)"
                    if result.llm_enabled else " · llm: off")
        if result.llm_errors:
            llm_note += f" ({len(result.llm_errors)} error(s))"
        print(f"\n{len(result.findings)} finding(s) · "
              f"{result.scan.files_scanned} file(s) · "
              f"{result.tokens.total} token(s) · "
              f"{result.duration_ms / 1000:.1f}s{llm_note}")
        for err in result.llm_errors:
            print(f"  llm: {err}", file=sys.stderr)
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    cfg = _load(args)
    directory = Path(args.directory).resolve()
    if not directory.is_dir():
        print(f"error: not a directory: {directory}", file=sys.stderr)
        return 2

    from phalanx.scanner.bench import format_table, run_bench

    with AuditLogger(cfg.audit_dir) as audit:
        budget = TokenBudget(cfg.budget.max_tokens)
        client = build_client(cfg.llm, stage="triage", warn=_warn)
        try:
            rows, raw = run_bench(directory, client=client, budget=budget,
                                  audit=audit, use_llm=not args.no_llm)
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.format == "json":
        print(json.dumps(raw, indent=2))
    else:
        print(f"challenge set: {directory}")
        print(format_table(rows))
        if raw["llm_errors"]:
            print("\nllm notes:")
            for e in raw["llm_errors"]:
                print(f"  - {e}")
    # exit 0 even with misses: the report is the product; CI gates come later
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    print("phalanx fix: not implemented yet — lands in Phase 3 (FIX + VERIFY).",
          file=sys.stderr)
    return 2


def cmd_sandbox_check(args: argparse.Namespace) -> int:
    cfg = _load(args)
    if args.image:
        from dataclasses import replace

        cfg = replace(cfg, sandbox=replace(cfg.sandbox, image=args.image))

    ok, reason = docker_available()
    if not ok:
        print(f"error: sandbox unavailable — {reason}", file=sys.stderr)
        return 1

    project = Path(args.project or ".").resolve()
    from phalanx.sandbox.docker_sandbox import DockerSandbox
    from phalanx.sandbox.runners import SandboxRunner

    with AuditLogger(cfg.audit_dir) as audit:
        sandbox = DockerSandbox(cfg.sandbox, audit=audit)
        try:
            sandbox.start(project)
            runner = SandboxRunner(sandbox, cfg.sandbox, audit=audit)
            check = runner.verify_network_isolation()
        finally:
            sandbox.destroy()

    print(render_network_check(check.isolated, check.evidence))
    return 0 if check.isolated else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    cfg = _load(args)
    print(f"phalanx {__version__}")
    print(f"python  : {sys.version.split()[0]}")
    print(f"config  : {args.config or 'phalanx.toml (defaults)'}")
    print(f"provider: {cfg.llm.provider} "
          f"(triage={cfg.llm.triage_model}, fix={cfg.llm.fix_model})")
    if cfg.llm.provider == "anthropic":
        import os

        if os.environ.get("ANTHROPIC_API_KEY"):
            print("api key : ANTHROPIC_API_KEY set")
        else:
            print("api key : ANTHROPIC_API_KEY missing (mock fallback)")
    ok, reason = semgrep_available()
    print(f"semgrep : {'ok' if ok else reason}")
    ok, reason = docker_available()
    print(f"docker  : {'ok' if ok else reason}")
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phalanx",
        description="AI security engineer for PHP — find, prove, fix, verify.")
    parser.add_argument("--version", action="version", version=f"phalanx {__version__}")
    parser.add_argument("--config", help="path to phalanx.toml")
    sub = parser.add_subparsers(dest="command", required=True)

    p_ask = sub.add_parser("ask", help="ask the agent questions about a PHP file")
    p_ask.add_argument("file", help="PHP file to analyze")
    p_ask.add_argument("question", help="question to answer")
    p_ask.add_argument("--provider", choices=["anthropic", "openai", "mock"])
    p_ask.add_argument("--budget", type=int, help="hard token cap")
    p_ask.add_argument("--no-sandbox", action="store_true",
                       help="read files from host instead of sandbox")
    p_ask.set_defaults(func=cmd_ask)

    p_scan = sub.add_parser("scan", help="FIND stage: Semgrep + optional LLM review")
    p_scan.add_argument("path", help="file or directory to scan")
    p_scan.add_argument("--format", choices=["terminal", "json", "sarif"],
                        default="terminal")
    p_scan.add_argument("--no-llm", action="store_true",
                        help="deterministic scan only (no LLM review layer)")
    p_scan.add_argument("--budget", type=int, help="hard token cap")
    p_scan.set_defaults(func=cmd_scan)

    p_bench = sub.add_parser("bench", help="score a challenge set vs ground truth")
    p_bench.add_argument("directory", help="challenge dir containing expected.json")
    p_bench.add_argument("--format", choices=["table", "json"], default="table")
    p_bench.add_argument("--no-llm", action="store_true",
                        help="baseline only (semgrep-only variant)")
    p_bench.add_argument("--budget", type=int, help="hard token cap")
    p_bench.set_defaults(func=cmd_bench)

    p_fix = sub.add_parser("fix", help="generate and verify fixes (Phase 3)")
    p_fix.add_argument("path", help="project directory")
    p_fix.set_defaults(func=cmd_fix)

    p_sbox = sub.add_parser("sandbox", help="sandbox operations")
    sbox_sub = p_sbox.add_subparsers(dest="sandbox_command", required=True)
    p_check = sbox_sub.add_parser("check", help="prove network isolation")
    p_check.add_argument("--project", help="project dir to load into sandbox")
    p_check.add_argument("--image", help="override sandbox image")
    p_check.set_defaults(func=cmd_sandbox_check)

    p_doc = sub.add_parser("doctor", help="environment report")
    p_doc.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
