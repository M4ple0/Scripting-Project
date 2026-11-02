
from __future__ import annotations

import json

from .models import SEVERITIES, Finding

_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[2m",
}
_RESET = "\033[0m"


def summarize(findings: list[Finding]) -> dict:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def format_text(findings: list[Finding], files_scanned: int, color: bool = False) -> str:
    def paint(text: str, severity: str) -> str:
        return f"{_COLORS[severity]}{text}{_RESET}" if color else text

    out: list[str] = []
    by_file: dict[str, list[Finding]] = {}
    for finding in findings:
        by_file.setdefault(finding.file, []).append(finding)

    for file_name, items in by_file.items():
        out.append(file_name)
        for f in items:
            badge = paint(f"[{f.severity.upper()}]", f.severity)
            cwe = f"  ({f.cwe})" if f.cwe else ""
            out.append(f"  line {f.line:<4} {badge} {f.rule_id}  {f.title}{cwe}")
            out.append(f"      code: {f.snippet}")
            out.append(f"      why:  {f.message}")
            out.append(f"      fix:  {f.recommendation}")
        out.append("")

    counts = summarize(findings)
    parts = [f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s]]
    detail = ", ".join(parts) if parts else "no findings"
    out.append(f"Scanned {files_scanned} input(s): {len(findings)} finding(s) ({detail})")
    return "\n".join(out)


def format_json(findings: list[Finding], files_scanned: int) -> str:
    return json.dumps(
        {
            "files_scanned": files_scanned,
            "summary": summarize(findings),
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
    )
