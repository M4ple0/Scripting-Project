"""SQL injection: queries built by gluing strings together instead of using parameters."""
from __future__ import annotations

from core.models import CodeInput, Finding

from .base import ANY, JS, PHP, PY, Rule, run_rules

NAME = "sql_injection"
DESCRIPTION = "SQL statements assembled with concatenation, formatting or f-strings"

_FIX = ("Use parameterised queries (placeholders such as ? or %s) and pass values separately "
        "instead of building the SQL text.")

RULES = [
    Rule(
        id="SQL001", title="Query built inside execute()", severity="high", cwe="CWE-89", languages=PY,
        pattern=(r"""\.(?:execute|executemany|executescript|raw)\s*\(\s*(?:[rb]?f(?:"[^"]*\{|'[^']*\{)"""
                 r"""|[rbu]?(?:"[^"]*"|'[^']*')\s*(?:%|\+|\.format\s*\())"""),
        message="The SQL passed to execute() is built with formatting or concatenation, so input can change the query.",
        recommendation=_FIX,
    ),
    Rule(
        id="SQL002", title="SQL string built dynamically", severity="medium", cwe="CWE-89", languages=ANY,
        pattern=(r"""(?i)^(?=.*\b(?:select\b.+\bfrom|insert\s+into|update\b.+\bset|delete\s+from)\b)"""
                 r"""(?=.*(?:["']\s*\+|\+\s*["']|["']\s*%\s*(?:\(|[A-Za-z_]\w*\s*(?:[,)\]]|$))"""
                 r"""|\.format\s*\(|\$\{|\bf["']))"""),
        message="A SQL statement is assembled from pieces at runtime. If any piece is user input it is injectable.",
        recommendation=_FIX,
    ),
    Rule(
        id="SQL003", title="PHP query uses request data", severity="high", cwe="CWE-89", languages=PHP,
        pattern=(r"""(?i)(?:\b(?:mysql_query|mysqli_query|pg_query)|->query)\s*\(.*"""
                 r"""(?:\$_(?:GET|POST|REQUEST|COOKIE)|["']\s*\.\s*\$)"""),
        message="A PHP database call includes request data or concatenated variables in the SQL.",
        recommendation="Use PDO or mysqli prepared statements with bound parameters.",
    ),
    Rule(
        id="SQL004", title="JavaScript query built with template or concatenation", severity="high",
        cwe="CWE-89", languages=JS,
        pattern=r"""\.(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+)""",
        message="A database call receives a string built from variables.",
        recommendation="Use placeholders ($1 or ?) and pass the values as the second argument.",
    ),
]


def check(code: CodeInput) -> list[Finding]:
    return run_rules(code, RULES)
