from __future__ import annotations

from dataclasses import asdict, dataclass

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


@dataclass
class CodeInput:

    name: str
    language: str
    text: str

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    snippet: str
    message: str
    recommendation: str
    cwe: str = ""

    def to_dict(self) -> dict:
        return asdict(self)
