
from __future__ import annotations

import json

from .models import SEVERITIES, SEVERITY_WEIGHTS, Finding

# ANSI escape codes that color terminal text by severity.
_COLORS = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[2m",
}
# ANSI code that turns terminal coloring back off.
_RESET = "\033[0m"


# Count findings per severity, e.g. {"high": 2, "info": 1}.
def summarize(findings: list[Finding]) -> dict:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def risk_score(findings: list[Finding]) -> int:
    return int(sum(SEVERITY_WEIGHTS[finding.severity] for finding in findings))


# Build the plain-text report a person reads in the terminal.
def format_text(findings: list[Finding], files_scanned: int, color: bool = False) -> str:
    # Wrap text in its severity color, or leave it plain if color is off.
    def paint(text: str, severity: str) -> str:
        return f"{_COLORS[severity]}{text}{_RESET}" if color else text

    out: list[str] = []
    # group findings under their file so the report reads as a file-by-file review
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
    # descending severity order so critical counts lead the summary line
    parts = [f"{counts[s]} {s}" for s in reversed(SEVERITIES) if counts[s]]
    detail = ", ".join(parts) if parts else "no findings"
    out.append(f"Scanned {files_scanned} input(s): {len(findings)} finding(s) ({detail})")
    score = risk_score(findings)
    average = float(score) / max(files_scanned, 1)
    out.append(f"Risk score: {str(score)} ({average:.1f} per input)")
    return "\n".join(out)


# Build the machine-readable JSON report for other programs to consume.
def format_json(findings: list[Finding], files_scanned: int) -> str:
    return json.dumps(
        {
            "files_scanned": files_scanned,
            "summary": summarize(findings),
            "risk_score": risk_score(findings),
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
    )
