"""Shared machinery for the rule scripts: the Rule type and the line scanner."""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

from core.models import CodeInput, Finding

# Shorthand language tags a rule lists in its languages field.
PY = ("python",)
JS = ("javascript",)
C = ("c", "cpp")
PHP = ("php",)
ANY = ("*",)

# Comment markers per language, used to skip lines that are only comments.
COMMENT_PREFIXES = {
    "python": ("#",),
    "shell": ("#",),
    "ruby": ("#",),
    "php": ("//", "#", "/*", "* ", "*/"),
}
_C_STYLE = ("//", "/*", "* ", "*/")
# C-family languages share one prefix set; assign it rather than repeating per language
for _lang in ("javascript", "c", "cpp", "java", "go"):
    COMMENT_PREFIXES[_lang] = _C_STYLE

# A line carrying one of these markers is deliberately ignored.
SUPPRESSION = re.compile(r"(?:nosec|noqa:\s*security|secure-review:\s*ignore)", re.I)


# One rule: a regex pattern plus the metadata reported when that pattern matches.
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


# Compile a regex once and cache it so the same pattern is never rebuilt.
@lru_cache(maxsize=None)
def _compile(pattern: str, flags: int):
    return re.compile(pattern, flags)


# Returns true when the line starts with a comment marker for that language.
def is_comment(line: str, language: str) -> bool:
    stripped = line.strip()
    if stripped == "*" and language in ("javascript", "c", "cpp", "java", "go", "php"):
        return True
    return stripped.startswith(COMMENT_PREFIXES.get(language, ("#", "//")))


# Rule selection helper: decides whether this rule should run on this language.
def applies(rule: Rule, language: str) -> bool:
    """Rules for one language are skipped on other languages, but code whose
    language could not be detected (e.g. a pasted snippet) gets every rule."""
    return "*" in rule.languages or language in rule.languages or language == "unknown"


# Wraps a matched line into a Finding carrying the rule's metadata.
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


# Checks each line of the input against every rule that applies to its language.
def run_rules(code: CodeInput, rules: list[Rule]) -> list[Finding]:
    """Check every code line against every applicable rule (one line at a time)."""
    # Rule selection: keep only the rules whose languages match this input.
    active = [rule for rule in rules if applies(rule, code.language)]
    findings: list[Finding] = []
    # Walk the file one line at a time, numbering lines from 1.
    for number, line in enumerate(code.lines, start=1):
        # blanks, comments and nosec/noqa markers never produce findings
        if not line.strip() or is_comment(line, code.language) or SUPPRESSION.search(line):
            continue
        # Regex matching: try each remaining rule's pattern against this line.
        for rule in active:
            # search() looks for the pattern anywhere in the line, not a full-line match
            if not _compile(rule.pattern, rule.flags).search(line):
                continue
            # an optional exclude pattern is a second regex: a line matching it is a
            # known false positive, so the rule stays silent
            if rule.exclude and _compile(rule.exclude, rule.flags).search(line):
                continue
            findings.append(make_finding(rule, code, number, line))
    return findings
