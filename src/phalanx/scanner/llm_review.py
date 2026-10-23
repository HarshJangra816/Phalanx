"""LLM review layer: logic flaws rules can't catch + second-guessing
deterministic hits (ARCHITECTURE.md §3.1).

The model sees ONE function-level slice (~50-150 lines), never a whole file,
and returns structured hypotheses — never facts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from phalanx.agent.budget import TokenBudget, Usage
from phalanx.agent.router import Message, ModelClient
from phalanx.findings import Finding, VulnClass
from phalanx.scanner.slicer import CodeSlice

VALID_CLASSES = {c.value for c in VulnClass if c != VulnClass.UNKNOWN} | {"logic"}

SYSTEM_PROMPT = """\
You are Phalanx's code-review layer for PHP security. Defensive-only.

You receive ONE function-level slice of PHP and optionally the deterministic
findings already reported for it. Your job:
 1. Second-guess the deterministic findings: is each one a plausible true
    positive given the code, or likely a false positive? (confidence 0..1)
 2. Spot logic flaws static rules miss: missing auth checks, IDOR, missing
    access control, unsafe deserialization, SSRF, weak crypto, session issues.

STRICT OUTPUT CONTRACT — reply with ONLY a JSON object, no prose, no fences:
{"findings": [{"class": "sqli|xss|cmdi|upload|lfi|logic",
  "line": <int>, "confidence": <0..1>, "reason": "<max 200 chars>"}]}

Rules:
 - "line" must be a line number inside the slice shown (absolute, as numbered).
 - Empty list is a valid answer when nothing looks wrong.
 - Analysis only: never write exploits, payloads, or PoC code.
"""


@dataclass
class ReviewOutcome:
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    usage: Usage = field(default_factory=Usage)
    model: str = ""
    raw: str = ""


def _extract_json(text: str) -> dict | None:
    """Pull the first JSON object out of a model reply (fences/notes tolerated)."""
    if not text:
        return None
    cleaned = re.sub(r"```(?:json)?", "", text).strip("` \n")
    for candidate in (cleaned, text):
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    start = cleaned.find("{")
    if start == -1:
        return None
    try:
        obj, _ = json.JSONDecoder().raw_decode(cleaned[start:])
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def _to_finding(item: dict, slice_: CodeSlice, model: str, tokens: int) -> Finding | None:
    if not isinstance(item, dict):
        return None
    klass = str(item.get("class", "")).strip().lower()
    if klass not in VALID_CLASSES:
        return None
    try:
        line = int(item.get("line", slice_.start_line))
    except (TypeError, ValueError):
        line = slice_.start_line
    line = max(slice_.start_line, min(line, slice_.end_line))
    try:
        confidence = float(item.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(confidence, 1.0))
    reason = str(item.get("reason", ""))[:500]
    return Finding(
        file=slice_.file,
        start_line=line,
        end_line=line,
        vuln_class=VulnClass(klass),
        confidence=round(confidence, 3),
        message=reason or "LLM review hypothesis",
        source="llm",
        model=model,
        tokens_used=tokens,
        evidence={"slice": slice_.to_dict()},
    )


def review_slice(client: ModelClient, budget: TokenBudget, slice_: CodeSlice,
                 hints: list[Finding] | None = None, audit: object | None = None,
                 max_tokens: int = 1500) -> ReviewOutcome:
    """Review one slice with the triage model; returns hypotheses.

    Raises BudgetExceeded only if the budget was ALREADY exhausted before the
    call; a call that trips the cap is charged (accounting stays honest) and
    the outcome is still returned.
    """
    outcome = ReviewOutcome(model=getattr(client, "default_model", client.name))

    parts = [f"File: {slice_.file}",
             f"Slice: {slice_.name} ({slice_.kind}), lines "
             f"{slice_.start_line}-{slice_.end_line} of {slice_.total_lines}",
             "", slice_.numbered()]
    if hints:
        parts += ["", "Deterministic findings to verify or refute:"]
        for h in hints:
            parts.append(f"- {h.file}:{h.start_line} [{h.vuln_class.value}] {h.message}")
    user_text = "\n".join(parts)

    fn = getattr(audit, "log", None)
    if callable(fn):
        fn("llm_review_start", file=slice_.file, lines=slice_.line_count)

    budget.check()
    completion = client.complete(
        system=SYSTEM_PROMPT,
        messages=[Message(role="user", content=user_text)],
        tools=None,
        max_tokens=max_tokens,
        temperature=0.0,
    )
    budget.charge(completion.usage, model=completion.model)
    outcome.usage = completion.usage
    outcome.model = completion.model or outcome.model
    outcome.raw = completion.text or ""

    payload = _extract_json(outcome.raw)
    if payload is None:
        outcome.error = "model did not return valid JSON"
    else:
        items = payload.get("findings", [])
        if isinstance(items, list):
            for item in items:
                f = _to_finding(item, slice_, outcome.model, completion.usage.total)
                if f is not None:
                    outcome.findings.append(f)
        else:
            outcome.error = "JSON 'findings' is not a list"

    if callable(fn):
        fn("llm_review_end", file=slice_.file, findings=len(outcome.findings),
           error=outcome.error, tokens=completion.usage.total)
    return outcome
