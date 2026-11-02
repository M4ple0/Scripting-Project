"""Dangerous functions and patterns: code execution, unsafe deserialisation, banned C calls, XSS sinks."""
from __future__ import annotations

from core.models import CodeInput, Finding

from .base import C, JS, PHP, PY, Rule, run_rules

NAME = "unsafe_functions"
DESCRIPTION = "eval/exec, unsafe deserialisation, banned C string functions, XSS sinks, path traversal"

_USER_PHP = r"""\$_(?:GET|POST|REQUEST|COOKIE)"""

RULES = [
    Rule(
        id="UNS001", title="eval()/exec() call", severity="high", cwe="CWE-95", languages=PY,
        pattern=r"""(?<![\w.])(?:eval|exec)\s*\(""",
        message="eval()/exec() run arbitrary code; with user-influenced input this is remote code execution.",
        recommendation="Use ast.literal_eval for data, or a dispatch table of allowed operations.",
    ),
    Rule(
        id="UNS002", title="eval() / new Function()", severity="high", cwe="CWE-95", languages=JS,
        pattern=r"""(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(""",
        message="Evaluating strings as code allows script injection.",
        recommendation="Parse data with JSON.parse and replace dynamic code with explicit logic.",
    ),
    Rule(
        id="UNS003", title="Unsafe deserialisation (pickle/marshal)", severity="high", cwe="CWE-502", languages=PY,
        pattern=r"""\b(?:pickle|cPickle|_pickle|dill|marshal)\.(?:loads?|Unpickler)\s*\(""",
        message="Loading untrusted pickle/marshal data can execute attacker-controlled code.",
        recommendation="Use a data-only format such as JSON, or sign and verify the data before loading.",
    ),
    Rule(
        id="UNS004", title="yaml.load without a safe loader", severity="high", cwe="CWE-502", languages=PY,
        pattern=r"""\byaml\.(?:load|load_all|unsafe_load)\s*\(""",
        exclude=r"""SafeLoader|safe_load|BaseLoader""",
        message="yaml.load can construct arbitrary Python objects from untrusted YAML.",
        recommendation="Use yaml.safe_load().",
    ),
    Rule(
        id="UNS005", title="gets() is never safe", severity="critical", cwe="CWE-242", languages=C,
        pattern=r"""(?<![\w.>:])gets\s*\(""",
        message="gets() cannot limit how much it reads, so it always allows a buffer overflow.",
        recommendation="Use fgets(buf, sizeof(buf), stdin).",
    ),
    Rule(
        id="UNS006", title="Unbounded C string function", severity="high", cwe="CWE-120", languages=C,
        pattern=r"""(?<![\w.>:])(?:strcpy|strcat|sprintf|vsprintf|stpcpy|wcscpy|wcscat)\s*\(""",
        message="This function does not check the destination size and can overflow the buffer.",
        recommendation="Use strncpy/strlcpy, strncat, snprintf with an explicit size, and check the result.",
    ),
    Rule(
        id="UNS007", title="scanf with an unbounded %s", severity="high", cwe="CWE-120", languages=C,
        pattern=r"""(?<![\w.>:])f?scanf\s*\(.*"[^"]*%s""",
        message="%s without a width reads as much as the input provides.",
        recommendation='Give a width, e.g. scanf("%63s", buf), or use fgets.',
    ),
    Rule(
        id="UNS008", title="Format string from a variable", severity="high", cwe="CWE-134", languages=C,
        pattern=(r"""(?<![\w.>:])(?:printf\s*\(\s*[A-Za-z_]\w*\s*\)"""
                 r"""|fprintf\s*\(\s*\w+\s*,\s*[A-Za-z_]\w*\s*\))"""),
        message="Passing a variable as the format string lets input such as %n or %x read or write memory.",
        recommendation='Always use a constant format: printf("%s", value).',
    ),
    Rule(
        id="UNS009", title="DOM write sink (innerHTML / document.write)", severity="medium", cwe="CWE-79",
        languages=JS,
        pattern=r"""\.(?:innerHTML|outerHTML)\s*\+?=|\bdocument\.write(?:ln)?\s*\(""",
        exclude=r"""(?:innerHTML|outerHTML)\s*=\s*["'][^"'+$<]*["']\s*;?\s*$""",
        message="Writing text into the DOM as HTML allows cross-site scripting when the text is user-controlled.",
        recommendation="Use textContent, or sanitise with a vetted library such as DOMPurify.",
    ),
    Rule(
        id="UNS010", title="PHP unserialize()", severity="high", cwe="CWE-502", languages=PHP,
        pattern=r"""(?<![\w>$:])unserialize\s*\(""",
        message="unserialize() on untrusted data enables object-injection attacks.",
        recommendation="Use json_decode() for data coming from users.",
    ),
    Rule(
        id="UNS011", title="PHP eval()", severity="critical", cwe="CWE-95", languages=PHP,
        pattern=r"""(?<![\w>$:.])eval\s*\(""",
        message="eval() executes a string as PHP code.",
        recommendation="Remove eval() and replace it with explicit logic.",
    ),
    Rule(
        id="UNS012", title="PHP include with request data", severity="high", cwe="CWE-98", languages=PHP,
        pattern=r"""(?<![\w>$:])(?:include|require)(?:_once)?\b.*""" + _USER_PHP,
        message="Including a file chosen by the request allows local/remote file inclusion.",
        recommendation="Map user choices to a fixed allow-list of files.",
    ),
    Rule(
        id="UNS013", title="PHP echoes request data", severity="medium", cwe="CWE-79", languages=PHP,
        pattern=r"""\b(?:echo|print)\b.*""" + _USER_PHP,
        exclude=r"""htmlspecialchars|htmlentities|intval|\(int\)|filter_var|esc_html""",
        message="Request data is written to the page without escaping (reflected XSS).",
        recommendation="Wrap output in htmlspecialchars($value, ENT_QUOTES, 'UTF-8').",
    ),
    Rule(
        id="UNS014", title="File access with a user-controlled path", severity="medium", cwe="CWE-22",
        languages=PY,
        pattern=(r"""\b(?:open|send_file|send_from_directory)\s*\(.*"""
                 r"""\brequest\.(?:args|form|values|files|json|GET|POST|cookies)\b"""),
        message="A file path comes from the request, which may allow ../ traversal to other files.",
        recommendation="Use os.path.basename, join to a fixed base directory and verify the resolved path stays inside it.",
    ),
    Rule(
        id="UNS015", title="render_template_string with built string", severity="high", cwe="CWE-1336",
        languages=PY,
        pattern=r"""\brender_template_string\s*\(.*(?:\+|%\s*[\w(]|\bf["']|\.format\s*\()""",
        message="Building a template from user text allows server-side template injection and XSS.",
        recommendation="Keep the template constant and pass user data as variables, e.g. render_template().",
    ),
]


def check(code: CodeInput) -> list[Finding]:
    return run_rules(code, RULES)
