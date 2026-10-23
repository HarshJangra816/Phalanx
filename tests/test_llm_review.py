import json

import pytest

from phalanx.agent.budget import BudgetExceeded, TokenBudget, Usage
from phalanx.agent.router import Completion
from phalanx.scanner.llm_review import _extract_json, review_slice
from phalanx.scanner.slicer import CodeSlice

SLICE = CodeSlice(file="a.php", name="vuln_fn", kind="function", start_line=10,
                  end_line=30, text="function vuln_fn() { /* code */ }",
                  total_lines=80)


class FakeClient:
    name = "fake"
    default_model = "fake-model"

    def __init__(self, text, usage=None):
        self.text = text
        self.usage = usage if usage is not None else Usage(100, 50)
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        return Completion(text=self.text, tool_calls=[], usage=self.usage,
                          model=self.default_model, stop_reason="end_turn")


def test_valid_json_produces_hypotheses():
    payload = {"findings": [
        {"class": "logic", "line": 12, "confidence": 0.8,
         "reason": "no auth check before action"},
        {"class": "sqli", "line": 99, "confidence": 1.7, "reason": "clamp me"},
        {"class": "not-a-class", "line": 11, "confidence": 0.5, "reason": "drop"},
        "garbage",
    ]}
    client = FakeClient(json.dumps(payload))
    out = review_slice(client, TokenBudget(10_000), SLICE)
    assert out.error == ""
    assert len(out.findings) == 2
    logic = next(f for f in out.findings if f.vuln_class.value == "logic")
    assert logic.start_line == 12
    assert logic.source == "llm"
    assert logic.status.value == "HYPOTHESIS"
    sqli = next(f for f in out.findings if f.vuln_class.value == "sqli")
    assert sqli.confidence == 1.0          # clamped
    assert sqli.start_line == 30           # line clamped into slice range


def test_markdown_fenced_json_is_tolerated():
    text = "Sure! Here is the review:\n```json\n" + json.dumps(
        {"findings": [{"class": "xss", "line": 10, "confidence": 0.7,
                       "reason": "echo"}]}) + "\n```"
    out = review_slice(FakeClient(text), TokenBudget(10_000), SLICE)
    assert len(out.findings) == 1


def test_garbage_reply_sets_error():
    out = review_slice(FakeClient("I cannot help with that."),
                       TokenBudget(10_000), SLICE)
    assert out.findings == []
    assert "valid JSON" in out.error


def test_hints_are_included_in_prompt():
    from phalanx.findings import Finding, VulnClass

    client = FakeClient('{"findings": []}')
    hint = Finding(file="a.php", start_line=11, end_line=11,
                   vuln_class=VulnClass.SQLI, message="semgrep says sqli")
    review_slice(client, TokenBudget(10_000), SLICE, hints=[hint])
    # FakeClient doesn't capture kwargs; assert via a capturing variant:
    capturing = CapturingClient('{"findings": []}')
    review_slice(capturing, TokenBudget(10_000), SLICE, hints=[hint])
    assert "semgrep says sqli" in capturing.last_messages[0].content
    assert "vuln_fn" in capturing.last_messages[0].content


class CapturingClient(FakeClient):
    def __init__(self, text):
        super().__init__(text)
        self.last_messages = []

    def complete(self, **kwargs):
        self.last_messages = kwargs["messages"]
        return super().complete(**kwargs)


def test_tokens_are_charged_to_budget():
    budget = TokenBudget(200)
    review_slice(FakeClient('{"findings": []}', usage=Usage(150, 40)),
                 budget, SLICE)
    assert budget.spent.total == 190


def test_exhausted_budget_raises_before_call():
    budget = TokenBudget(100)
    budget.charge(Usage(100, 0))
    client = FakeClient('{"findings": []}')
    with pytest.raises(BudgetExceeded):
        review_slice(client, budget, SLICE)
    assert client.calls == 0


def test_extract_json_variants():
    assert _extract_json('{"findings": []}') == {"findings": []}
    assert _extract_json('```\n{"findings": []}\n```') == {"findings": []}
    assert _extract_json('noise {"findings": [1]} trailing') == {"findings": [1]}
    assert _extract_json("") is None
    assert _extract_json("no json here") is None
