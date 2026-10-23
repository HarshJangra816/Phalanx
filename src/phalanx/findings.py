"""Core findings data model (ARCHITECTURE.md §4).

A finding is a HYPOTHESIS until a sandboxed PoC proves it (CONFIRMED).
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class VulnClass(StrEnum):
    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    UPLOAD = "upload"
    LFI = "lfi"
    LOGIC = "logic"
    UNKNOWN = "unknown"


class FindingStatus(StrEnum):
    HYPOTHESIS = "HYPOTHESIS"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    FIXED = "FIXED"
    UNFIXED = "UNFIXED"


@dataclass
class Finding:
    file: str
    start_line: int
    end_line: int
    vuln_class: VulnClass
    confidence: float = 0.5
    status: FindingStatus = FindingStatus.HYPOTHESIS
    message: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)  # PoC + captured output
    patch: str = ""  # unified diff
    verification: dict[str, Any] = field(default_factory=dict)  # {reexploit, tests, attempts}
    tokens_used: int = 0
    model: str = ""
    source: str = ""  # semgrep | llm | agent
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["vuln_class"] = self.vuln_class.value
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        payload = dict(data)
        payload["vuln_class"] = VulnClass(payload.get("vuln_class", VulnClass.UNKNOWN.value))
        payload["status"] = FindingStatus(payload.get("status", FindingStatus.HYPOTHESIS.value))
        return cls(**payload)
