import json

from phalanx.agent.audit import AuditLogger


def test_writes_valid_jsonl(tmp_path):
    with AuditLogger(tmp_path) as audit:
        audit.log("scan_start", target="lab")
        audit.log("scan_end", findings=3)

    lines = audit.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    records = [json.loads(ln) for ln in lines]
    assert records[0]["event"] == "scan_start"
    assert records[0]["data"]["target"] == "lab"
    assert records[0]["run_id"] == records[1]["run_id"]
    assert records[1]["seq"] == 2


def test_append_only_across_instances(tmp_path):
    with AuditLogger(tmp_path, run_id="fixed123") as a:
        a.log("one")
    with AuditLogger(tmp_path, run_id="fixed123") as a:
        a.log("two")

    lines = (tmp_path / "audit-fixed123.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(ln)["event"] for ln in lines] == ["one", "two"]


def test_step_logs_start_and_end(tmp_path):
    with AuditLogger(tmp_path) as audit, audit.step("exploit", script_bytes=10):
        pass
    events = [json.loads(ln)["event"] for ln in
              audit.path.read_text().strip().splitlines()]
    assert events == ["exploit_start", "exploit_end"]


def test_step_captures_failure(tmp_path):
    with AuditLogger(tmp_path) as audit:
        try:
            with audit.step("llm_request"):
                raise RuntimeError("boom")
        except RuntimeError:
            pass
    record = json.loads(audit.path.read_text().strip().splitlines()[-1])
    assert record["data"]["status"] == "error"
    assert "boom" in record["data"]["error"]
