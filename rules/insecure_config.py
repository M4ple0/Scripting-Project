"""Insecure configuration: debug mode, disabled TLS checks, open CORS, loose permissions."""
from __future__ import annotations

from core.models import CodeInput, Finding

from .base import ANY, PY, Rule, run_rules

NAME = "insecure_config"
DESCRIPTION = "Debug mode, disabled certificate checks, wildcard CORS/hosts, world-writable files, temp files"

RULES = [
    Rule(
        id="CFG001", title="Debug mode enabled", severity="medium", cwe="CWE-489", languages=PY,
        pattern=r"""\bapp\.run\s*\(.*\bdebug\s*=\s*True|^\s*DEBUG\s*=\s*True\b""",
        message="Debug mode exposes stack traces and, in Flask, an interactive console.",
        recommendation="Turn debug off outside development, ideally driven by an environment variable.",
    ),
    Rule(
        id="CFG002", title="TLS certificate verification disabled", severity="high", cwe="CWE-295", languages=ANY,
        pattern=(r"""(?i)\bverify\s*=\s*False\b|_create_unverified_context|\brejectUnauthorized\s*:\s*false"""
                 r"""|\bCURLOPT_SSL_VERIFY(?:PEER|HOST)\s*,\s*(?:false|0)|\bInsecureSkipVerify\s*:\s*true"""
                 r"""|\bNODE_TLS_REJECT_UNAUTHORIZED\b.*\b0\b|\bcheck_hostname\s*=\s*False\b|\bCERT_NONE\b"""),
        message="Without certificate checks any attacker on the network path can impersonate the server.",
        recommendation="Keep verification on and add the proper CA bundle if you use a private CA.",
    ),
    Rule(
        id="CFG003", title="Binds to all network interfaces", severity="low", cwe="CWE-1327", languages=ANY,
        pattern=r"""["']0\.0\.0\.0["']""",
        message="The service listens on every interface, which may expose it beyond the intended network.",
        recommendation="Bind to 127.0.0.1 or a specific interface unless public exposure is intended.",
    ),
    Rule(
        id="CFG004", title="Wildcard CORS policy", severity="medium", cwe="CWE-942", languages=ANY,
        pattern=(r"""(?i)Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*|\borigins?\s*:\s*["']\*["']"""
                 r"""|\ballow_origins\s*=\s*\[\s*["']\*["']|\bCORS\s*\(.*\borigins?\s*=\s*["']\*["']"""),
        message="Any website may call this API from a visitor's browser.",
        recommendation="List the specific origins that need access; never combine * with credentials.",
    ),
    Rule(
        id="CFG005", title="World-writable file permissions", severity="medium", cwe="CWE-732", languages=ANY,
        pattern=r"""(?i)\bchmod\s*\(.*\b0?o?(?:777|666)\b|\bchmod\s+(?:-\w+\s+)?(?:777|666)\b""",
        message="Every local user can modify the file or directory.",
        recommendation="Grant the minimum permissions, e.g. 0o600 for files and 0o700 for directories.",
    ),
    Rule(
        id="CFG006", title="Insecure temporary file", severity="medium", cwe="CWE-377", languages=ANY,
        pattern=r"""\b(?:tempfile\.mktemp|tmpnam|tempnam|mktemp)\s*\(""",
        message="The file name is predictable and can be hijacked between creation of the name and use.",
        recommendation="Use tempfile.NamedTemporaryFile / mkstemp (or mkstemp() in C), which create the file atomically.",
    ),
    Rule(
        id="CFG007", title="ALLOWED_HOSTS allows every host", severity="medium", cwe="CWE-16", languages=PY,
        pattern=r"""\bALLOWED_HOSTS\s*=\s*\[\s*["']\*["']""",
        message="Host-header validation is effectively switched off.",
        recommendation="List the real host names of the site.",
    ),
    Rule(
        id="CFG008", title="CSRF protection disabled", severity="medium", cwe="CWE-352", languages=ANY,
        pattern=r"""(?i)@csrf_exempt\b|\bWTF_CSRF_ENABLED\s*=\s*False|\bcsrf\s*:\s*false""",
        message="State-changing requests can be forged from other sites.",
        recommendation="Keep CSRF protection on and exempt only endpoints that use token authentication.",
    ),
]


def check(code: CodeInput) -> list[Finding]:
    return run_rules(code, RULES)
