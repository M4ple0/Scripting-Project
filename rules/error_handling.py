"""Error handling and edge cases: swallowed exceptions, missing timeouts, unchecked allocations."""
from __future__ import annotations

import re

from core.models import CodeInput, Finding

from .base import ANY, C, JS, PY, SUPPRESSION, Rule, is_comment, make_finding, run_rules

NAME = "error_handling"
DESCRIPTION = "Bare/empty except blocks, calls without timeouts, unchecked malloc, asserts used as checks"

RULES = [
    Rule(
        id="ERR001", title="Bare except clause", severity="medium", cwe="CWE-755", languages=PY,
        pattern=r"""^\s*except\s*:""",
        message="A bare except also catches KeyboardInterrupt and SystemExit and hides the real failure.",
        recommendation="Catch the specific exceptions you expect and log or re-raise the rest.",
    ),
    Rule(
        id="ERR002", title="Exception swallowed silently", severity="medium", cwe="CWE-390", languages=PY,
        pattern="",  # multi-line check, see _swallowed_exceptions
        message="The except block does nothing, so failures (including security-relevant ones) go unnoticed.",
        recommendation="Log the error and either handle it properly or let it propagate.",
    ),
    Rule(
        id="ERR003", title="Empty catch block", severity="medium", cwe="CWE-390", languages=JS,
        pattern=r"""\bcatch\s*(?:\(\s*\w*\s*\))?\s*\{\s*\}""",
        message="The catch block is empty, so errors disappear without a trace.",
        recommendation="Log or handle the error, or remove the try/catch if it is not needed.",
    ),
    Rule(
        id="ERR004", title="HTTP request without a timeout", severity="low", cwe="CWE-400", languages=PY,
        pattern=r"""\brequests\.(?:get|post|put|delete|head|patch|request)\s*\(""",
        exclude=r"""\btimeout\s*=""",
        message="Without a timeout the program can hang forever on a slow or malicious server.",
        recommendation="Pass timeout=<seconds> to every network call.",
    ),
    Rule(
        id="ERR005", title="Allocation result not checked", severity="medium", cwe="CWE-476", languages=C,
        pattern="",  # multi-line check, see _unchecked_allocations
        message="malloc/calloc/realloc can return NULL; using the pointer unchecked crashes or worse.",
        recommendation="Test the pointer against NULL immediately and handle the failure.",
    ),
    Rule(
        id="ERR006", title="assert used for input or permission checks", severity="low", cwe="CWE-617",
        languages=PY,
        pattern=r"""^\s*assert\b.*(?:request|user_input|input\(|password|auth|permission|is_admin)""",
        message="assert statements are removed when Python runs with -O, so the check vanishes.",
        recommendation="Use an explicit if-statement that raises an exception.",
    ),
]

_EXCEPT_LINE = re.compile(r"^\s*except\b.*:\s*$")
_ALLOC_LINE = re.compile(r"=\s*(?:\(\s*[\w\s*]+\)\s*)?(?:malloc|calloc|realloc)\s*\(")
_CHECK_WORDS = re.compile(r"\bNULL\b|\bif\b|!\s*\w|\bassert\b|\bnullptr\b")


def _next_code_line(lines: list[str], index: int):
    for offset in range(index + 1, len(lines)):
        if lines[offset].strip():
            return offset, lines[offset]
    return None, ""


def _rule(rule_id: str) -> Rule:
    return next(r for r in RULES if r.id == rule_id)


def _swallowed_exceptions(code: CodeInput) -> list[Finding]:
    if code.language not in ("python", "unknown"):
        return []
    lines, findings = code.lines, []
    for index, line in enumerate(lines):
        if is_comment(line, "python") or SUPPRESSION.search(line) or not _EXCEPT_LINE.match(line):
            continue
        _, following = _next_code_line(lines, index)
        if following.strip() in ("pass", "...", "continue"):
            findings.append(make_finding(_rule("ERR002"), code, index + 1, line))
    return findings


def _unchecked_allocations(code: CodeInput) -> list[Finding]:
    if code.language not in ("c", "cpp", "unknown"):
        return []
    lines, findings = code.lines, []
    for index, line in enumerate(lines):
        if is_comment(line, "c") or SUPPRESSION.search(line) or not _ALLOC_LINE.search(line):
            continue
        _, following = _next_code_line(lines, index)
        if not _CHECK_WORDS.search(following):
            findings.append(make_finding(_rule("ERR005"), code, index + 1, line))
    return findings


def check(code: CodeInput) -> list[Finding]:
    simple_rules = [r for r in RULES if r.pattern]
    return run_rules(code, simple_rules) + _swallowed_exceptions(code) + _unchecked_allocations(code)
