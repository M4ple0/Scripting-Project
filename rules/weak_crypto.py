"""Weak cryptography: broken hashes and ciphers, predictable randomness, small keys, old TLS."""
from __future__ import annotations

from core.models import CodeInput, Finding

from .base import ANY, Rule, run_rules

NAME = "weak_crypto"
DESCRIPTION = "MD5/SHA-1, DES/RC4/ECB, predictable random numbers, short keys, obsolete TLS"

RULES = [
    Rule(
        id="CRY001", title="Weak hash function (MD5 / SHA-1)", severity="medium", cwe="CWE-328", languages=ANY,
        pattern=(r"""(?i)\b(?:hashlib\.)?(?:md5|sha1)\s*\("""
                 r"""|\b(?:hashlib\.new|createHash|MessageDigest\.getInstance)\s*\(\s*["'](?:md5|sha-?1)["']"""),
        message="MD5 and SHA-1 are broken for security use. For passwords they are also far too fast.",
        recommendation="Use SHA-256 or better for integrity, and bcrypt, scrypt or Argon2 for passwords.",
    ),
    Rule(
        id="CRY002", title="Weak cipher or ECB mode", severity="high", cwe="CWE-327", languages=ANY,
        pattern=(r"""(?i)\b(?:des3?|arc4|rc4|arc2|blowfish)\.new\s*\(|\bMODE_ECB\b|\baes-\d{3}-ecb\b"""
                 r"""|\bcreateCipher(?:iv)?\s*\(\s*["'](?:des|rc4|bf)|\bEVP_(?:des|rc4|bf|rc2)_\w+"""),
        message="DES, RC4 and Blowfish are obsolete and ECB mode leaks patterns in the data.",
        recommendation="Use AES-GCM or ChaCha20-Poly1305 from a maintained library.",
    ),
    Rule(
        id="CRY003", title="Predictable random number used for a secret", severity="medium", cwe="CWE-338",
        languages=ANY,
        pattern=(r"""(?i)^(?=.*(?:\brandom\.(?:random|randint|choice|choices|randrange|getrandbits)"""
                 r"""|\bMath\.random|\bmt_rand|\brand)\s*\()"""
                 r"""(?=.*(?:token|passw|secret|session|otp|nonce|salt|api_?key|reset|csrf))"""),
        message="General-purpose random generators are predictable and must not create tokens, passwords or keys.",
        recommendation="Use secrets (Python), crypto.randomBytes (Node), random_bytes (PHP) or the OS CSPRNG.",
    ),
    Rule(
        id="CRY004", title="Short RSA / key size", severity="medium", cwe="CWE-326", languages=ANY,
        pattern=(r"""(?i)\bkey_size\s*=\s*(?:512|768|1024)\b|\bRSA\.generate\s*\(\s*(?:512|768|1024)\b"""
                 r"""|\bmodulusLength\s*:\s*(?:512|768|1024)\b"""),
        message="This key length is considered too short today.",
        recommendation="Use RSA keys of at least 2048 bits (3072 recommended) or an elliptic-curve key.",
    ),
    Rule(
        id="CRY005", title="Obsolete SSL/TLS version", severity="high", cwe="CWE-327", languages=ANY,
        pattern=(r"""\bPROTOCOL_(?:SSLv2|SSLv3|SSLv23|TLSv1|TLSv1_1)\b|\bSSLv[23]_(?:client_|server_)?method\b"""
                 r"""|\bTLSv1(?:_1)?_(?:client_|server_)?method\b|\bminVersion\s*:\s*["']TLSv1(?:\.1)?["']"""),
        message="SSLv2/3 and TLS 1.0/1.1 have known weaknesses and are deprecated.",
        recommendation="Require TLS 1.2 or newer (ssl.create_default_context() does this).",
    ),
]


def check(code: CodeInput) -> list[Finding]:
    return run_rules(code, RULES)
