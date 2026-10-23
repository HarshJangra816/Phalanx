import json

from phalanx.agent.router import (
    Message,
    MockClient,
    ToolCall,
    build_client,
    to_anthropic_messages,
    to_anthropic_tools,
    to_openai_messages,
    to_openai_tools,
)
from phalanx.config import LLMConfig


def _sample_messages():
    return [
        Message(role="user", content="read the file"),
        Message(role="assistant", content="reading", tool_calls=[
            ToolCall(id="t1", name="read_file", arguments={"path": "a.php"})]),
        Message(role="tool", content="1| <?php", tool_call_id="t1"),
    ]


# -- wire-format conversion -------------------------------------------------


def test_to_anthropic_messages_shapes():
    out = to_anthropic_messages(_sample_messages())
    assert out[0] == {"role": "user", "content": "read the file"}
    types = [b["type"] for b in out[1]["content"]]
    assert types == ["text", "tool_use"]
    assert out[2]["content"][0]["type"] == "tool_result"
    assert out[2]["content"][0]["tool_use_id"] == "t1"


def test_to_anthropic_tools_keeps_json_schema():
    tools = [{"name": "read_file", "description": "d",
              "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}}}]
    out = to_anthropic_tools(tools)
    assert out[0]["input_schema"]["type"] == "object"


def test_to_openai_tools_wraps_function():
    tools = [{"name": "run_scan", "description": "scan", "input_schema": {"type": "object"}}]
    out = to_openai_tools(tools)
    assert out[0]["type"] == "function"
    assert out[0]["function"]["name"] == "run_scan"
    assert out[0]["function"]["parameters"] == {"type": "object"}


def test_to_openai_messages_tool_role():
    out = to_openai_messages(_sample_messages())
    assert out[2]["role"] == "tool"
    assert out[2]["tool_call_id"] == "t1"
    # assistant tool_calls arguments serialized as JSON string
    args = out[1]["tool_calls"][0]["function"]["arguments"]
    assert json.loads(args) == {"path": "a.php"}


# -- mock client ------------------------------------------------------------


def test_mock_reads_target_file_then_answers():
    client = MockClient()
    system = "You are Phalanx.\n\nTarget file: src/app.php\nProject root: /x"
    first = client.complete(system=system, messages=[Message(role="user", content="what is this?")],
                            tools=[{"name": "read_file", "description": "",
                                    "input_schema": {"type": "object"}}])
    assert first.tool_calls[0].name == "read_file"
    assert first.tool_calls[0].arguments["path"] == "src/app.php"

    msgs = [
        Message(role="user", content="what is this?"),
        Message(role="assistant", tool_calls=first.tool_calls),
        Message(role="tool", content="1| <?php\n2| function greet() {}", tool_call_id="t1"),
    ]
    second = client.complete(system=system, messages=msgs,
                             tools=[{"name": "read_file", "description": "",
                                     "input_schema": {"type": "object"}}])
    assert second.tool_calls == []
    assert "greet" in second.text
    assert second.usage.total > 0


# -- router -----------------------------------------------------------------


def test_build_client_mock():
    client = build_client(LLMConfig(provider="mock"))
    assert client.name == "mock"


def test_build_client_unknown_provider():
    import pytest

    from phalanx.agent.router import ProviderError

    with pytest.raises(ProviderError):
        build_client(LLMConfig(provider="nope"), allow_mock_fallback=False)


def test_build_client_falls_back_to_mock_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    warnings = []
    client = build_client(LLMConfig(provider="anthropic"), warn=warnings.append)
    assert client.name == "mock"
    assert warnings and "ANTHROPIC_API_KEY" in warnings[0]


def test_build_client_routes_stage_models(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    triage = build_client(LLMConfig(provider="anthropic", triage_model="cheap",
                                    fix_model="strong"), stage="triage")
    fix = build_client(LLMConfig(provider="anthropic", triage_model="cheap",
                                 fix_model="strong"), stage="fix")
    assert triage.default_model == "cheap"
    assert fix.default_model == "strong"


def test_model_id_present_in_request_payloads(monkeypatch):
    """Regression: payloads once carried model=''; assert the ID is filled."""
    from phalanx.agent.router import AnthropicClient

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    seen = {}

    def fake_post(url, headers, payload, timeout):
        seen.update(payload)
        return {"content": [], "usage": {}, "model": payload["model"],
                "stop_reason": "end_turn"}

    monkeypatch.setattr("phalanx.agent.router._post_json", fake_post)
    client = AnthropicClient(model="claude-haiku-4-5")
    client.complete(system="s", messages=[Message(role="user", content="hi")])
    assert seen["model"] == "claude-haiku-4-5"

    # explicit per-call override wins
    client.complete(system="s", messages=[Message(role="user", content="hi")],
                    model="claude-sonnet-4-5")
    assert seen["model"] == "claude-sonnet-4-5"
