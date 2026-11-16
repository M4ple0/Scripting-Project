"""Hardcoded credentials: passwords, API keys, tokens and private keys in source."""
from __future__ import annotations

import math
import re

from core.models import CodeInput, Finding

from .base import ANY, SUPPRESSION, Rule, is_comment, run_rules

NAME = "hardcoded_secrets"
DESCRIPTION = "Passwords, API keys, tokens and private keys written into the source code"

_PLACEHOLDER = (
    r"""(?i)(?:os\.environ|getenv|process\.env|changeme|change_me|placeholder|example|"""
    r"""your[_-]?(?:pass|pwd|key|token)|<[^>]+>|\*{3,}|\{\{|x{6,})"""
)
_FIX = "Load secrets from environment variables or a secrets manager and rotate the exposed value."

RULES = [
    Rule(
        id="SEC001", title="Hardcoded password", severity="high", cwe="CWE-798", languages=ANY,
        pattern=r"""(?i)\b\w*(?:passw(?:or)?d|pwd|passphrase)\w*["']?\s*[:=]\s*["'][^"'\s]{4,}["']""",
        exclude=_PLACEHOLDER + r"""|(?i:_(?:field|label|prompt|help|hint|name|type|url|policy|regex|min|max|length|confirm)\w*["']?\s*[:=])""",
        message="A password appears to be written directly in the source code.",
        recommendation=_FIX,
    ),
    Rule(
        id="SEC002", title="Hardcoded API key or secret", severity="high", cwe="CWE-798", languages=ANY,
        pattern=(r"""(?i)\b\w*(?:api[_-]?key|apikey|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|"""
                 r"""client[_-]?secret|private[_-]?key)\w*["']?\s*[:=]\s*["'][A-Za-z0-9_\-/+=.]{12,}["']"""),
        exclude=_PLACEHOLDER,
        message="An API key, token or secret appears to be written directly in the source code.",
        recommendation=_FIX,
    ),
    Rule(
        id="SEC003", title="AWS access key ID", severity="critical", cwe="CWE-798", languages=ANY,
        pattern=r"""\b(?:AKIA|ASIA)[0-9A-Z]{16}\b""",
        message="This matches the format of an AWS access key ID.",
        recommendation="Revoke the key in AWS IAM now and use IAM roles or environment-based credentials.",
    ),
    Rule(
        id="SEC004", title="Private key in source", severity="critical", cwe="CWE-321", languages=ANY,
        pattern=r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY""",
        message="A private key is embedded in the source code.",
        recommendation="Remove the key from the repository, treat it as compromised and generate a new one.",
    ),
    Rule(
        id="SEC005", title="Credential compared with a literal", severity="high", cwe="CWE-798", languages=ANY,
        pattern=r"""(?i)\b\w*(?:passw(?:or)?d|pwd|secret|token)\w*\s*(?:===|==|!=)\s*["'][^"']{3,}["']""",
        exclude=r"""(?i)(?:os\.environ|getenv|process\.env|\bnone\b)""",
        message="A credential is compared against a fixed string, so the credential is visible in the code.",
        recommendation="Compare against a salted hash from a user store using a constant-time check.",
    ),
    Rule(
        id="SEC006", title="Known access-token format", severity="critical", cwe="CWE-798", languages=ANY,
        pattern=(r"""\b(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|xox[abprs]-[A-Za-z0-9-]{10,}|"""
                 r"""sk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_\-]{35})"""),
        message="This string matches the format of a live GitHub, Slack, Stripe or Google token.",
        recommendation="Revoke the token with the provider immediately and load tokens from the environment.",
    ),
    Rule(
        id="SEC007", title="Credentials inside a URL", severity="high", cwe="CWE-798", languages=ANY,
        pattern=r"""(?i)\b[a-z][a-z0-9+.\-]*://[^/\s:@"']+:[^/\s:@"']+@""",
        exclude=r"""[{$%<]""",
        message="A URL contains a username and password.",
        recommendation="Keep credentials out of URLs; pass them separately from configuration.",
    ),
]

_ENTROPY_RULE = Rule(
    id="SEC008", title="High-entropy string near a secret-like name", severity="medium",
    cwe="CWE-798", languages=ANY, pattern="", message=(
        "A long random-looking string is assigned next to a name such as key, secret or token."),
    recommendation=_FIX,
)
_NAME_HINT = re.compile(r"(?i)(?:key|secret|token|passw|credential|auth)")
_LONG_STRING = re.compile(r"""["']([A-Za-z0-9+/=_\-]{24,})["']""")
_FROM_ENV = re.compile(r"(?i)(?:os\.environ|getenv|process\.env)")


def _entropy(text: str) -> float:
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in (text.count(c) for c in set(text)))


def _entropy_findings(code: CodeInput) -> list[Finding]:
    findings = []
    for number, line in enumerate(code.lines, start=1):
        if is_comment(line, code.language) or SUPPRESSION.search(line) or _FROM_ENV.search(line):
            continue
        if not _NAME_HINT.search(line):
            continue
        for match in _LONG_STRING.finditer(line):
            if _entropy(match.group(1)) >= 4.0:
                findings.append(Finding(
                    rule_id=_ENTROPY_RULE.id, title=_ENTROPY_RULE.title,
                    severity=_ENTROPY_RULE.severity, file=code.name, line=number,
                    snippet=line.strip()[:200], message=_ENTROPY_RULE.message,
                    recommendation=_ENTROPY_RULE.recommendation, cwe=_ENTROPY_RULE.cwe,
                ))
                break
    return findings


RULES.append(_ENTROPY_RULE)


def check(code: CodeInput) -> list[Finding]:
    return run_rules(code, RULES[:-1]) + _entropy_findings(code)
