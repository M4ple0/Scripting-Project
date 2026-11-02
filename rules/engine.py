"""Discovers the rule scripts and runs them against code."""
from __future__ import annotations

import importlib
import pkgutil
import warnings
from functools import lru_cache
from pathlib import Path

from core.models import SEVERITY_RANK, CodeInput, Finding

_NOT_RULE_SCRIPTS = {"base", "engine"}


@lru_cache(maxsize=None)
def load_rule_modules() -> tuple:
    """Import every rule script in this package and check it follows the contract."""
    modules = []
    for info in pkgutil.iter_modules([str(Path(__file__).parent)]):
        if info.name.startswith("_") or info.name in _NOT_RULE_SCRIPTS:
            continue
        module = importlib.import_module(f"{__package__}.{info.name}")
        missing = [a for a in ("NAME", "DESCRIPTION", "RULES", "check") if not hasattr(module, a)]
        if missing:
            warnings.warn(f"rule script {info.name!r} ignored, missing: {', '.join(missing)}")
            continue
        modules.append(module)
    return tuple(modules)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """One finding per line and weakness type; keep the most severe one."""
    best: dict[tuple, Finding] = {}
    for finding in findings:
        key = (finding.file, finding.line, finding.cwe or finding.rule_id)
        current = best.get(key)
        if current is None or SEVERITY_RANK[finding.severity] > SEVERITY_RANK[current.severity]:
            best[key] = finding
    return list(best.values())


def analyze(code: CodeInput, modules=None) -> list[Finding]:
    """Run all rule scripts on one input and return its findings, ordered by line."""
    findings: list[Finding] = []
    for module in modules or load_rule_modules():
        try:
            findings.extend(module.check(code))
        except Exception as exc:  # a broken rule script must not stop the whole scan
            warnings.warn(f"rule script {module.__name__} failed on {code.name}: {exc}")
    findings = _dedupe(findings)
    findings.sort(key=lambda f: (f.line, -SEVERITY_RANK[f.severity], f.rule_id))
    return findings


def analyze_many(inputs: list[CodeInput]) -> list[Finding]:
    results: list[Finding] = []
    for code in inputs:
        results.extend(analyze(code))
    return results


def list_rules() -> list[tuple]:
    """(script name, description, Rule) for every rule, for ``--list-rules``."""
    rows = []
    for module in load_rule_modules():
        for rule in module.RULES:
            rows.append((module.NAME, module.DESCRIPTION, rule))
    return rows
