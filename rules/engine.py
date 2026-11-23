"""Discovers the rule scripts and runs them against code."""
from __future__ import annotations

import importlib
import pkgutil
import warnings
from functools import lru_cache
from pathlib import Path

from core.models import SEVERITY_RANK, CodeInput, Finding

# Names of modules in this package that are infrastructure, not rule scripts.
_NOT_RULE_SCRIPTS = {"base", "engine"}


# Module discovery: import every rule script once and cache the result.
@lru_cache(maxsize=None)
def load_rule_modules() -> tuple:
    """Import every rule script in this package and check it follows the contract."""
    modules = []
    # Scan the directory holding this file for importable rule scripts.
    for info in pkgutil.iter_modules([str(Path(__file__).parent)]):
        # skip helpers: base holds shared types, engine is this file
        if info.name.startswith("_") or info.name in _NOT_RULE_SCRIPTS:
            continue
        module = importlib.import_module(f"{__package__}.{info.name}")
        # Contract check: a script missing these attributes is ignored with a warning.
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
        # Group by file, line and weakness so duplicates land in one slot.
        key = (finding.file, finding.line, finding.cwe or finding.rule_id)
        current = best.get(key)
        # Keep whichever of the two findings has the higher severity rank.
        if current is None or SEVERITY_RANK[finding.severity] > SEVERITY_RANK[current.severity]:
            best[key] = finding
    return list(best.values())


def analyze(code: CodeInput, modules=None) -> list[Finding]:
    """Run all rule scripts on one input and return its findings, ordered by line."""
    findings: list[Finding] = []
    # Run each rule script in turn, falling back to warnings if one breaks.
    for module in load_rule_modules() if modules is None else modules:
        try:
            findings.extend(module.check(code))
        except Exception as exc:  # a broken rule script must not stop the whole scan
            warnings.warn(f"rule script {module.__name__} failed on {code.name}: {exc}")
    # Deduplication: collapse repeated hits for the same line and weakness.
    findings = _dedupe(findings)
    # line order first, then worst severity, then rule id for a stable listing
    findings.sort(key=lambda f: (f.line, -SEVERITY_RANK[f.severity], f.rule_id))
    return findings


# Scans a batch of inputs and returns every finding they produced.
def analyze_many(inputs: list[CodeInput]) -> list[Finding]:
    results: list[Finding] = []
    for code in inputs:
        results.extend(analyze(code))
    return results


# Builds the rows shown by --list-rules from every discovered rule script.
def list_rules() -> list[tuple]:
    """(script name, description, Rule) for every rule, for ``--list-rules``."""
    rows = []
    for module in load_rule_modules():
        for rule in module.RULES:
            rows.append((module.NAME, module.DESCRIPTION, rule))
    return rows
