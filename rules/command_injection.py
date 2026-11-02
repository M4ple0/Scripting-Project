"""OS command injection: shell commands built from variable data."""
from __future__ import annotations

from core.models import CodeInput, Finding

from .base import C, JS, PHP, PY, Rule, run_rules

NAME = "command_injection"
DESCRIPTION = "Shell commands that include variable or user-controlled text"

RULES = [
    Rule(
        id="CMD001", title="os.system / os.popen with a dynamic command", severity="high",
        cwe="CWE-78", languages=PY,
        pattern=r"""\bos\.(?:system|popen)\s*\(\s*(?!["'][^"'{%]*["']\s*\))""",
        message="A shell command is built from non-constant text, so crafted input can run extra commands.",
        recommendation="Use subprocess.run([...]) with a list of arguments and no shell, and validate the input.",
    ),
    Rule(
        id="CMD002", title="subprocess with shell=True", severity="high", cwe="CWE-78", languages=PY,
        pattern=(r"""\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(.*\bshell\s*=\s*True"""
                 r"""|\bsubprocess\.(?:getoutput|getstatusoutput)\s*\("""),
        message="The command runs through a shell, which interprets characters such as ; | and $().",
        recommendation="Pass the command as a list and leave shell=False.",
    ),
    Rule(
        id="CMD003", title="Node exec() with a dynamic command", severity="high", cwe="CWE-78", languages=JS,
        pattern=(r"""(?:(?<![\w.])|child_process\.)(?:exec|execSync)\s*\(\s*"""
                 r"""(?:`[^`]*\$\{|["'][^"']*["']\s*\+|[A-Za-z_]\w*\s*[,)])"""),
        message="exec() runs its argument in a shell and the command is built from variables.",
        recommendation="Use execFile() or spawn() with an argument array.",
    ),
    Rule(
        id="CMD004", title="PHP shell function with request data", severity="high", cwe="CWE-78", languages=PHP,
        pattern=(r"""(?<![\w>$:])(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(.*"""
                 r"""(?:\$_(?:GET|POST|REQUEST|COOKIE)|["']\s*\.\s*\$)"""),
        message="A shell command includes request data or concatenated variables.",
        recommendation="Avoid shell calls; if unavoidable, validate against an allow-list and use escapeshellarg().",
    ),
    Rule(
        id="CMD005", title="system()/popen() with a non-literal command", severity="high", cwe="CWE-78",
        languages=C,
        pattern=r"""(?<![\w.>:])(?:system|popen)\s*\(\s*(?!")""",
        message="A shell command is passed to system()/popen() as a variable.",
        recommendation="Use execve()/execvp() with an argument vector and validate every argument.",
    ),
]


def check(code: CodeInput) -> list[Finding]:
    return run_rules(code, RULES)
