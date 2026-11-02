"""Shared machinery for the rule scripts: the Rule type and the line scanner."""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from core.models import CodeInput, Finding

PY = ("python",)
JS = ("javascript",)
C = ("c", "cpp")
PHP = ("php",)
ANY = ("*",)

COMMENT_PREFIXES = {
    "python": ("#",),
    "shell": ("#",),
    "ruby": ("#",),
    "php": ("//", "#", "/*", "* ", "*/"),
}
_C_STYLE = ("//", "/*", "* ", "*/")
for _lang in ("javascript", "c", "cpp", "java", "go"):
    COMMENT_PREFIXES[_lang] = _C_STYLE

# A line carrying one of these markers is deliberately ignored.
SUPPRESSION = re.compile(r"(?:nosec|noqa:\s*security|secure-review:\s*ignore)", re.I)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    cwe: str
    languages: tuple
    pattern: str
    message: str
    recommendation: str
    exclude: str = ""      # a line matching this is NOT reported
    flags: int = 0


@lru_cache(maxsize=None)
def _compile(pattern: str, flags: int):
    return re.compile(pattern, flags)


def is_comment(line: str, language: str) -> bool:
    stripped = line.strip()
    if stripped == "*" and language in ("javascript", "c", "cpp", "java", "go", "php"):
        return True
    return stripped.startswith(COMMENT_PREFIXES.get(language, ("#", "//")))


def applies(rule: Rule, language: str) -> bool:
    """Rules for one language are skipped on other languages, but code whose
    language could not be detected (e.g. a pasted snippet) gets every rule."""
    return "*" in rule.languages or language in rule.languages or language == "unknown"


def make_finding(rule: Rule, code: CodeInput, line_number: int, line: str) -> Finding:
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity,
        file=code.name,
        line=line_number,
        snippet=line.strip()[:200],
        message=rule.message,
        recommendation=rule.recommendation,
        cwe=rule.cwe,
    )


def run_rules(code: CodeInput, rules: list[Rule]) -> list[Finding]:
    """Check every code line against every applicable rule (one line at a time)."""
    active = [rule for rule in rules if applies(rule, code.language)]
    findings: list[Finding] = []
    for number, line in enumerate(code.lines, start=1):
        if not line.strip() or is_comment(line, code.language) or SUPPRESSION.search(line):
            continue
        for rule in active:
            if not _compile(rule.pattern, rule.flags).search(line):
                continue
            if rule.exclude and _compile(rule.exclude, rule.flags).search(line):
                continue
            findings.append(make_finding(rule, code, number, line))
    return findings
