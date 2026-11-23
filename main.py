#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import os
import sys

from core.chunker import chunk_code
from core.input_handler import EXTENSION_LANGUAGES, MAX_BYTES_ENV_VAR, MAX_FILE_BYTES, load_inputs
from core.models import SEVERITIES, SEVERITY_RANK
from core.report import format_json, format_text

VERSION = "2.0"
MINIMUM_PYTHON = (3, 8)


def add_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("paths", nargs="*",
                        help="files or folders to read ('-' reads standard input)")
    parser.add_argument("--stdin", action="store_true", help="also read code from standard input")
    parser.add_argument("--paste", action="store_true",
                        help="type or paste code interactively (finish with a line saying END)")
    parser.add_argument("--language", choices=sorted(set(EXTENSION_LANGUAGES.values())),
                        help="force the language instead of detecting it")
    parser.add_argument("--max-kb", help="skip files larger than this many kilobytes "
                                         f"(default {MAX_FILE_BYTES // 1024}, or set {MAX_BYTES_ENV_VAR})")


def kilobytes_to_bytes(text):
    try:
        limit = float(text) * 1024
    except ValueError:
        return None
    # NaN, inf and values whose byte total overflows float cannot become an int
    if not math.isfinite(limit):
        return None
    return int(limit)


def probability(text):
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number")
    # NaN, inf and anything outside the inclusive 0..1 range is not a probability
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a probability in the inclusive range 0 to 1")
    return value


def python_version_text() -> str:
    return ".".join(str(part) for part in sys.version_info[:3])


def output_matches_input(output_path, inputs) -> bool:
    """Check whether the output file is one of the files being analysed."""

    output_path = os.path.realpath(os.path.abspath(output_path))

    for code in inputs:
        # Ignore stdin and pasted snippets, which aren't filesystem paths.
        if code.name.startswith("<") and code.name.endswith(">"):
            continue

        input_path = os.path.realpath(os.path.abspath(code.name))

        # Check whether both paths refer to the same underlying file.
        try:
            if os.path.samefile(output_path, input_path):
                return True
        except OSError:
            # Fall back to normalized path comparison.
            if os.path.normcase(output_path) == os.path.normcase(input_path):
                return True

    return False



def emit(text: str, path=None, inputs=None) -> bool:
    if not path:
        print(text)
        return True

    # Prevent overwriting source files.
    if inputs and output_matches_input(path, inputs):
        print(
            f"error: output file '{path}' is also an input file. "
            "Choose a different output path.",
            file=sys.stderr
        )
        return False

    folder = os.path.dirname(os.path.abspath(path))

    if not os.path.isdir(folder):
        print(f"error: the folder {folder} does not exist", file=sys.stderr)
        return False

    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")

    except OSError as exc:
        print(f"error: cannot write {path} ({exc.strerror or exc})", file=sys.stderr)
        return False

    print(
        f"report written to {path} ({os.path.getsize(path):,} bytes)",
        file=sys.stderr
    )

    return True



def gather(args):
    """Load the requested input and print any warnings. Returns None when nothing was readable."""
    use_stdin = args.stdin or "-" in args.paths
    paths = [p for p in args.paths if p != "-"]
    max_bytes = None
    if args.max_kb is not None:
        max_bytes = kilobytes_to_bytes(args.max_kb)
        if not max_bytes or max_bytes <= 0:
            print(f"error: --max-kb needs a positive number, got {args.max_kb!r}", file=sys.stderr)
            return None
    result = load_inputs(paths, use_stdin=use_stdin, paste=args.paste, language=args.language,
                         max_bytes=max_bytes)
    for warning in result.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if not result.inputs:
        print("error: no readable code to analyse. Give a file or folder, '-' for stdin, "
              "or --paste.", file=sys.stderr)
        return None
    return result.inputs


def cmd_read(args) -> int:
    inputs = gather(args)
    if inputs is None:
        return 2
    print(f"{'input':<40} {'language':<11} {'lines':>6} {'chars':>8} {'chunks':>7}")
    for code in inputs:
        chunks = chunk_code(code)
        print(f"{code.name[:40]:<40} {code.language:<11} {len(code.lines):>6} "
              f"{len(code.text):>8} {len(chunks):>7}")
        if args.chunks:
            for chunk in chunks:
                print(f"    lines {chunk.start_line}-{chunk.end_line}")
    print(f"\n{len(inputs)} input(s) ready for analysis.")
    return 0

def meets_severity(severity, minimum):
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[minimum]

def cmd_rules(args) -> int:
    from rules.engine import analyze_many, list_rules

    if args.list_rules:
        current = None
        for script, description, rule in list_rules():
            if script != current:
                current = script
                print(f"\n{script}  -  {description}")
            langs = ",".join(rule.languages)
            print(f"  {rule.id}  {rule.severity:<8} {langs:<10} {rule.title}")
        return 0

    inputs = gather(args)
    if inputs is None:
        return 2
    # --min-severity filters the findings first; --fail-on is checked afterwards
    # against only the findings that survived that filter
findings = [
    f for f in analyze_many(inputs)
    if meets_severity(f.severity, args.min_severity)
]
    if args.format == "json":
        report = format_json(findings, len(inputs))
    else:
        use_color = sys.stdout.isatty() and not args.no_color and not args.output
        report = format_text(findings, len(inputs), color=use_color)
    if not emit(report, args.output, inputs):
        return 2
if args.fail_on and any(
    meets_severity(f.severity, args.fail_on) for f in findings
):
    return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="main.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {VERSION} (python {python_version_text()})")
    sub = parser.add_subparsers(dest="command", required=True)
    # each subparser stores its handler in args.func; main() dispatches on it

    read = sub.add_parser("read", help="step 1: take input and show how it was parsed")
    add_input_args(read)
    read.add_argument("--chunks", action="store_true", help="list the review chunks of each input")
    read.set_defaults(func=cmd_read)

    rules = sub.add_parser("rules", help="step 2: rule-based security analysis")
    add_input_args(rules)
    rules.add_argument("--list-rules", action="store_true", help="show every rule and exit")
    rules.add_argument("--format", choices=["text", "json"], default="text")
    rules.add_argument("--min-severity", choices=SEVERITIES, default="info",
                       help="hide findings below this severity")
    rules.add_argument("--fail-on", choices=SEVERITIES,
                       help="exit with status 1 if a finding at/above this severity exists")
    rules.add_argument("--no-color", action="store_true")
    rules.add_argument("--output", metavar="FILE", help="write the report to a file instead of the screen")
    rules.set_defaults(func=cmd_rules)
    return parser


def main(argv=None) -> int:
    if sys.version_info < MINIMUM_PYTHON:
        needed = ".".join(str(part) for part in MINIMUM_PYTHON)
        print(f"error: Python {needed} or newer is required, this is {python_version_text()}",
              file=sys.stderr)
        return 2
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
