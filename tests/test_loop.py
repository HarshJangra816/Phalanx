
import pytest

from phalanx.agent.audit import AuditLogger
from phalanx.agent.budget import TokenBudget
from phalanx.agent.loop import AgentLoop
from phalanx.agent.router import Completion, MockClient, Usage
from phalanx.agent.tools import ToolContext, ToolRegistry
from phalanx.config import PhalanxConfig


@pytest.fixture
def project(tmp_path):
    (tmp_path / "app.php").write_text(
        "<?php\nfunction greet() {\n    echo 'hi';\n}\n", encoding="utf-8")
    return tmp_path


def make_loop(project, budget_tokens=200_000, client=None, audit=None, allow_edit=False):
    cfg = PhalanxConfig()
    ctx = ToolContext(root=project, config=cfg, audit=audit, allow_edit=allow_edit)
    registry = ToolRegistry(ctx)
    budget = TokenBudget(budget_tokens)
    loop = AgentLoop(client or MockClient(), registry, budget, audit=audit)
    return loop, budget


def test_loop_answers_about_php_file(project, tmp_path):
    with AuditLogger(tmp_path / "audit") as audit:
        loop, _ = make_loop(project, audit=audit)
        result = loop.run("what does this file do?",
                          system_extra="Target file: app.php")

    assert result.answer
    assert "greet" in result.answer
    assert result.tool_calls == 1          # one read_file
    assert result.stopped == "end_turn"
    assert result.usage.total > 0


def test_loop_writes_audit_trail(project, tmp_path):
    import json

    with AuditLogger(tmp_path / "audit") as audit:
        loop, _ = make_loop(project, audit=audit)
        loop.run("summarize", system_extra="Target file: app.php")
    names = [json.loads(ln)["event"] for ln in audit.path.read_text().splitlines()]
    assert "agent_start" in names
    assert "llm_response" in names
    assert "tool_call" in names
    assert "tool_result" in names
    assert "agent_end" in names


def test_loop_stops_gracefully_on_budget(project):
    class BigClient:
        name = "big"

        def complete(self, **kwargs):
            return Completion(text="answer", tool_calls=[], usage=Usage(5000, 100),
                              model="big", stop_reason="end_turn")

    loop, budget = make_loop(project, budget_tokens=1000, client=BigClient())
    result = loop.run("q", system_extra="Target file: app.php")
    assert result.stopped == "budget"
    assert "budget" in result.answer


def test_loop_handles_provider_error(project):
    class BrokenClient:
        name = "broken"

        def complete(self, **kwargs):
            raise RuntimeError("api down")

    loop, _ = make_loop(project, client=BrokenClient())
    result = loop.run("q")
    assert result.stopped == "error"
    assert "api down" in result.answer


def test_loop_max_turns_terminates(project):
    class LoopingClient:
        name = "loopy"

        def __init__(self):
            self.n = 0

        def complete(self, **kwargs):
            self.n += 1
            from phalanx.agent.router import ToolCall

            return Completion(text="", tool_calls=[
                ToolCall(id=f"c{self.n}", name="read_file", arguments={"path": "app.php"})],
                usage=Usage(10, 1), model="loopy", stop_reason="tool_use")

    loop, _ = make_loop(project, client=LoopingClient())
    loop.max_turns = 5
    result = loop.run("q")
    assert result.stopped == "max_turns"
    assert result.tool_calls == 5
