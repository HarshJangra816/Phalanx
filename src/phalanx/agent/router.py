"""Provider-agnostic model router.

Normalized message/tool-call types in; provider wire formats out.
Providers implemented over stdlib HTTP only (zero required deps):
  - Anthropic Messages API (default: Haiku triage / Sonnet fix, prompt caching on)
  - OpenAI Chat Completions
  - Mock (offline, deterministic — tests and no-API-key demos)

Model choice is config, not architecture (ARCHITECTURE.md §1.5).
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Protocol

from phalanx.agent.budget import Usage
from phalanx.config import LLMConfig


class ProviderError(RuntimeError):
    """Raised when an LLM provider call fails."""


# ---------------------------------------------------------------------------
# Normalized wire types
# ---------------------------------------------------------------------------


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Message:
    """Normalized chat message.

    role: "user" | "assistant" | "tool"
    tool_calls: present on assistant messages that request tools
    tool_call_id: present on role="tool" result messages
    """

    role: str
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_calls:
            data["tool_calls"] = [
                {"id": tc.id, "name": tc.name, "arguments": tc.arguments} for tc in self.tool_calls
            ]
        if self.tool_call_id:
            data["tool_call_id"] = self.tool_call_id
        return data


@dataclass
class Completion:
    text: str | None
    tool_calls: list[ToolCall]
    usage: Usage
    model: str
    stop_reason: str  # "tool_use" | "end_turn" | "stop" | ...


class ModelClient(Protocol):
    """What the agent loop needs from any provider."""

    name: str
    default_model: str

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        model: str | None = None,
    ) -> Completion: ...


# ---------------------------------------------------------------------------
# HTTP helper (stdlib only)
# ---------------------------------------------------------------------------


def _post_json(url: str, headers: dict[str, str], payload: dict[str, Any],
               timeout: int) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={
        "content-type": "application/json", **headers,
    }, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed URLs
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # noqa: TRY400 - surface provider error body
        detail = exc.read().decode("utf-8", errors="replace")[:2000]
        raise ProviderError(f"{url} returned HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderError(f"request to {url} failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------


def to_anthropic_messages(messages: list[Message]) -> list[dict[str, Any]]:
    """Convert normalized messages to Anthropic /v1/messages format."""
    out: list[dict[str, Any]] = []
    for msg in messages:
        if msg.role == "user":
            out.append({"role": "user", "content": msg.content})
        elif msg.role == "assistant":
            blocks: list[dict[str, Any]] = []
            if msg.content:
                blocks.append({"type": "text", "text": msg.content})
            for tc in msg.tool_calls:
                blocks.append({"type": "tool_use", "id": tc.id, "name": tc.name,
                               "input": tc.arguments})
            out.append({"role": "assistant", "content": blocks or msg.content})
        elif msg.role == "tool":
            out.append({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": msg.tool_call_id or "",
                    "content": msg.content,
                }],
            })
    return out


def to_anthropic_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Registry specs are already JSON-schema shaped; map to Anthropic tool form."""
    return [
        {"name": t["name"], "description": t.get("description", ""),
         "input_schema": t.get("input_schema", {"type": "object", "properties": {}})}
        for t in tools
    ]


class AnthropicClient:
    """Anthropic Messages API client with prompt caching on the system prefix."""

    API_URL = "https://api.anthropic.com/v1/messages"
    API_VERSION = "2023-06-01"

    def __init__(self, api_key: str | None = None, timeout: int = 120,
                 model: str = "claude-haiku-4-5") -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.timeout = timeout
        self.default_model = model
        self.name = "anthropic"
        if not self.api_key:
            raise ProviderError("ANTHROPIC_API_KEY is not set")

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        model: str | None = None,
    ) -> Completion:
        payload: dict[str, Any] = {
            "model": model or self.default_model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            # Cache the stable system prefix (ARCHITECTURE.md §6).
            "system": [{"type": "text", "text": system,
                        "cache_control": {"type": "ephemeral"}}],
            "messages": to_anthropic_messages(messages),
        }
        if tools:
            payload["tools"] = to_anthropic_tools(tools)
        data = _post_json(self.API_URL, {
            "x-api-key": self.api_key,
            "anthropic-version": self.API_VERSION,
        }, payload, self.timeout)
        return _parse_anthropic_response(data)


def _parse_anthropic_response(data: dict[str, Any]) -> Completion:
    text_parts: list[str] = []
    tool_calls: list[ToolCall] = []
    for block in data.get("content", []):
        if block.get("type") == "text":
            text_parts.append(block.get("text", ""))
        elif block.get("type") == "tool_use":
            tool_calls.append(ToolCall(
                id=block.get("id", ""), name=block.get("name", ""),
                arguments=block.get("input") or {},
            ))
    usage = data.get("usage", {})
    return Completion(
        text="\n".join(text_parts) or None,
        tool_calls=tool_calls,
        usage=Usage(int(usage.get("input_tokens", 0)), int(usage.get("output_tokens", 0))),
        model=data.get("model", ""),
        stop_reason=data.get("stop_reason", ""),
    )


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------


def to_openai_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {"type": "function", "function": {
            "name": t["name"],
            "description": t.get("description", ""),
            "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
        }}
        for t in tools
    ]


def to_openai_messages(messages: list[Message]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for msg in messages:
        if msg.role == "tool":
            out.append({"role": "tool", "tool_call_id": msg.tool_call_id or "",
                        "content": msg.content})
        elif msg.role == "assistant":
            entry: dict[str, Any] = {"role": "assistant", "content": msg.content or None}
            if msg.tool_calls:
                entry["tool_calls"] = [
                    {"id": tc.id, "type": "function", "function": {
                        "name": tc.name,
                        "arguments": json.dumps(tc.arguments),
                    }}
                    for tc in msg.tool_calls
                ]
            out.append(entry)
        else:
            out.append({"role": "user", "content": msg.content})
    return out


class OpenAIClient:
    """OpenAI Chat Completions client (works with OpenAI-compatible gateways)."""

    def __init__(self, api_key: str | None = None, base_url: str | None = None,
                 timeout: int = 120, model: str = "gpt-4o-mini") -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        base = base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.url = base.rstrip("/") + "/chat/completions"
        self.timeout = timeout
        self.default_model = model
        self.name = "openai"
        if not self.api_key:
            raise ProviderError("OPENAI_API_KEY is not set")

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        model: str | None = None,
    ) -> Completion:
        convo = [{"role": "system", "content": system}, *to_openai_messages(messages)]
        payload: dict[str, Any] = {
            "model": model or self.default_model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": convo,
        }
        if tools:
            payload["tools"] = to_openai_tools(tools)
        data = _post_json(self.url, {"authorization": f"Bearer {self.api_key}"},
                          payload, self.timeout)
        return _parse_openai_response(data)


def _parse_openai_response(data: dict[str, Any]) -> Completion:
    try:
        choice = data["choices"][0]
        msg = choice["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ProviderError(f"unexpected OpenAI response shape: {str(data)[:500]}") from exc
    tool_calls = []
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function", {})
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except json.JSONDecodeError:
            args = {"_raw": fn.get("arguments")}
        tool_calls.append(ToolCall(id=tc.get("id", ""), name=fn.get("name", ""),
                                   arguments=args))
    usage = data.get("usage", {})
    return Completion(
        text=msg.get("content") or None,
        tool_calls=tool_calls,
        usage=Usage(int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))),
        model=data.get("model", ""),
        stop_reason=choice.get("finish_reason", ""),
    )


# ---------------------------------------------------------------------------
# Mock (offline, deterministic)
# ---------------------------------------------------------------------------


class MockClient:
    """Deterministic offline provider for tests and no-API-key demos.

    Behaves like a minimal agent: asks to read the target file named in the
    system prompt, then answers from the tool result. Charges small fake
    usage so budget accounting is exercised end-to-end.
    """

    _FOCUS_RE = re.compile(r"Target file:\s*(\S+\.php)")
    _FN_RE = re.compile(r"function\s+(&)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")

    def __init__(self) -> None:
        self.name = "mock"
        self.default_model = "mock"

    def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        tools: list[dict[str, Any]] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        model: str | None = None,
    ) -> Completion:
        tool_names = {t["name"] for t in (tools or [])}
        has_results = any(m.role == "tool" for m in messages)

        if not has_results and "read_file" in tool_names:
            match = self._FOCUS_RE.search(system)
            if match:
                call = ToolCall(
                    id=f"mock-{len(messages)}", name="read_file",
                    arguments={"path": match.group(1)},
                )
                return Completion(None, [call], Usage(120, 20), "mock", "tool_use")

        # Answer from the last tool result (if any).
        evidence = ""
        for msg in reversed(messages):
            if msg.role == "tool":
                evidence = msg.content
                break
        lines = [ln for ln in evidence.splitlines() if ln.strip()]
        functions = sorted({m.group(2) for m in self._FN_RE.finditer(evidence)})
        question = next((m.content for m in reversed(messages) if m.role == "user"), "")
        answer = (
            f"(offline mock answer — configure an API key for real analysis)\n"
            f"Question: {question}\n"
            f"File lines: {len(lines)}\n"
            f"Functions found: {', '.join(functions) if functions else 'none'}\n"
            f"Excerpt:\n" + "\n".join(lines[:20])
        )
        return Completion(answer, [], Usage(200, 120), "mock", "end_turn")


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


def build_client(cfg: LLMConfig, stage: str = "triage",
                 allow_mock_fallback: bool = True, warn: Any = None) -> ModelClient:
    """Construct the provider client for the configured provider + stage.

    `stage` selects the tiered model: "triage" -> cheap model, "fix" -> strong
    model (ARCHITECTURE.md §6 token strategy).
    If the configured provider's API key is missing and `allow_mock_fallback`,
    degrade to MockClient with a warning (keeps the loop runnable offline).
    """
    provider = cfg.provider.lower()
    model = cfg.fix_model if stage == "fix" else cfg.triage_model
    try:
        if provider == "anthropic":
            return AnthropicClient(timeout=cfg.request_timeout, model=model)
        if provider == "openai":
            return OpenAIClient(timeout=cfg.request_timeout, model=model)
        if provider == "mock":
            return MockClient()
        raise ProviderError(f"unknown provider: {provider!r} (expected anthropic|openai|mock)")
    except ProviderError as exc:
        if allow_mock_fallback and provider != "mock" and "API_KEY" in str(exc):
            if warn:
                warn(f"phalanx: {exc}; falling back to offline mock provider")
            return MockClient()
        raise
