"""Output layer: terminal, JSON, SARIF, PR-ready Markdown (Phase 1-3)."""

from __future__ import annotations

import sys

from phalanx.findings import Finding

_COLORS = {"red": "\033[31m", "yellow": "\033[33m", "green": "\033[32m",
           "cyan": "\033[36m", "dim": "\033[2m", "reset": "\033[0m"}


def _c(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_COLORS[color]}{text}{_COLORS['reset']}"


def color_enabled() -> bool:
    return sys.stdout.isatty()


def render_findings(findings: list[Finding], color: bool | None = None) -> str:
    if color is None:
        color = color_enabled()
    if not findings:
        return _c("no findings", "green", color)
    lines = []
    for f in findings:
        loc = _c(f"{f.file}:{f.start_line}-{f.end_line}", "cyan", color)
        klass = _c(f.vuln_class.value, "yellow", color)
        lines.append(f"  {loc}  [{klass}]  {f.message}")
    return "\n".join(lines)


def render_answer(answer: str, stopped: str, tokens: int, model: str) -> str:
    parts = [answer]
    parts.append(_c(f"\n— {model or 'unknown'} · {tokens} tokens · stop={stopped}",
                    "dim", color_enabled()))
    return "\n".join(parts)


def render_network_check(isolated: bool, evidence: str) -> str:
    if isolated:
        head = _c("✔ SANDBOX ISOLATED", "green", color_enabled())
    else:
        head = _c("✘ SANDBOX REACHABLE — DO NOT RUN EXPLOITS", "red", color_enabled())
    return f"{head}\n  evidence: {evidence}"
