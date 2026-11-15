from __future__ import annotations

from dataclasses import asdict, dataclass

# Severity levels ordered from least to most serious.
SEVERITIES = ["info", "low", "medium", "high", "critical"]
# rank lets severities be compared with < / >= instead of string ordering
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
SEVERITY_WEIGHTS = {"info": 0, "low": 1, "medium": 3, "high": 7, "critical": 10}


# One piece of code (a file or pasted snippet) ready to be scanned.
@dataclass
class CodeInput:

    name: str
    language: str
    text: str

    # Split the stored text into a list of individual lines.
    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()


# A single problem found in the code, with everything the report needs.
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

    # Plain dict form, ready to be serialized as JSON.
    def to_dict(self) -> dict:
        return asdict(self)
