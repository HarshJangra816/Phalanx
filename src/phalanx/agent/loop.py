"""Agent tool-loop — the LangGraph-style core of Phalanx.

State machine stages: FIND -> PROVE -> FIX -> VERIFY -> DELIVER (ARCHITECTURE.md §2).
Phase 0 implements the generic tool loop over the fixed tool surface;
stage orchestration lands with Phases 1-3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from phalanx.agent.budget import BudgetExceeded, TokenBudget, Usage
from phalanx.agent.router import Message, ModelClient
from phalanx.agent.tools import ToolRegistry

MAX_TOOL_TURNS = 16

SYSTEM_PROMPT = """\
You are Phalanx, an AI security engineer for PHP. Defensive-only tool.

Rules:
- You operate ONLY on the user's own code (already provided in the project).
- Proof-of-concept exploits must be SAFE: read-a-canary / extract-a-marker class
  (marker format PHALANX_CANARY{...}). Never destructive, never exfiltrate real data.
- All execution happens inside an isolated sandbox; never ask for host execution.
- Prefer evidence over speculation: read the code before concluding.
- Keep answers concise and cite file:line.
"""


class Stage(StrEnum):
    FIND = "FIND"
    PROVE = "PROVE"
    FIX = "FIX"
    VERIFY = "VERIFY"
    DELIVER = "DELIVER"


@dataclass
class AgentResult:
    answer: str
    transcript: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: int = 0
    usage: Usage = field(default_factory=Usage)
    stopped: str = "end_turn"  # end_turn | budget | max_turns | error
    model: str = ""


class AgentLoop:
    """Drives one agent run: LLM <-> tools until a final answer or a stop."""

    def __init__(self, client: ModelClient, registry: ToolRegistry,
                 budget: TokenBudget, audit: Any = None,
                 max_turns: int = MAX_TOOL_TURNS) -> None:
        self.client = client
        self.registry = registry
        self.budget = budget
        self.audit = audit
        self.max_turns = max_turns

    def _log(self, event: str, **data: Any) -> None:
        fn = getattr(self.audit, "log", None)
        if callable(fn):
            fn(event, **data)

    def build_system(self, extra: str = "") -> str:
        parts = [SYSTEM_PROMPT]
        if extra:
            parts.append(extra)
        parts.append(f"Token budget remaining: {self.budget.remaining}.")
        return "\n\n".join(parts)

    def run(self, prompt: str, system_extra: str = "") -> AgentResult:
        messages: list[Message] = [Message(role="user", content=prompt)]
        system = self.build_system(system_extra)
        tools = self.registry.schemas()
        result = AgentResult(answer="")
        self._log("agent_start", provider=self.client.name, prompt_chars=len(prompt))

        for turn in range(self.max_turns):
            try:
                self.budget.check()
            except BudgetExceeded:
                result.stopped = "budget"
                result.answer = self._partial_answer(messages, "budget exhausted")
                break

            try:
                completion = self.client.complete(
                    system=system, messages=messages, tools=tools,
                    max_tokens=4096, temperature=0.0)
            except Exception as exc:  # noqa: BLE001 - graceful stop, keep transcript
                result.stopped = "error"
                result.answer = f"agent stopped: provider error: {exc}"
                self._log("llm_error", error=str(exc))
                break

            try:
                self.budget.charge(completion.usage, model=completion.model)
            except BudgetExceeded:
                # The call happened; record it, then stop gracefully.
                result.usage = result.usage.add(completion.usage)
                result.stopped = "budget"
                result.answer = self._partial_answer(
                    messages, f"budget exhausted after {result.usage.total} tokens")
                self._log("llm_response", model=completion.model,
                          usage={"in": completion.usage.input_tokens,
                                 "out": completion.usage.output_tokens},
                          tool_calls=len(completion.tool_calls), stop="budget")
                break

            result.usage = result.usage.add(completion.usage)
            result.model = completion.model or result.model
            self._log("llm_response", model=completion.model,
                      usage={"in": completion.usage.input_tokens,
                             "out": completion.usage.output_tokens},
                      tool_calls=len(completion.tool_calls))

            if not completion.tool_calls:
                result.answer = completion.text or ""
                result.stopped = "end_turn"
                break

            # Record the assistant turn, then execute each requested tool.
            messages.append(Message(role="assistant", content=completion.text or "",
                                    tool_calls=completion.tool_calls))
            result.transcript.append({
                "turn": turn, "text": completion.text,
                "tool_calls": [{"name": tc.name, "arguments": tc.arguments}
                               for tc in completion.tool_calls],
            })
            for tc in completion.tool_calls:
                result.tool_calls += 1
                output = self.registry.dispatch(tc.name, tc.arguments)
                messages.append(Message(role="tool", content=output,
                                        tool_call_id=tc.id))
        else:
            result.stopped = "max_turns"
            result.answer = self._partial_answer(messages, "max turns reached")

        self._log("agent_end", stopped=result.stopped, tool_calls=result.tool_calls,
                  tokens=result.usage.total)
        return result

    def _partial_answer(self, messages: list[Message], reason: str) -> str:
        last_text = ""
        for msg in reversed(messages):
            if msg.role == "assistant" and msg.content:
                last_text = msg.content
                break
        n_tools = sum(1 for m in messages if m.role == "tool")
        header = f"[stopped early: {reason}; {n_tools} tool results collected]"
        return f"{header}\n{last_text}".strip()
