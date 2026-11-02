#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

from core.chunker import chunk_code
from core.input_handler import EXTENSION_LANGUAGES, load_inputs
from core.models import SEVERITIES, SEVERITY_RANK
from core.report import format_json, format_text


def add_input_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("paths", nargs="*",
                        help="files or folders to read ('-' reads standard input)")
    parser.add_argument("--stdin", action="store_true", help="also read code from standard input")
    parser.add_argument("--paste", action="store_true",
                        help="type or paste code interactively (finish with a line saying END)")
    parser.add_argument("--language", choices=sorted(set(EXTENSION_LANGUAGES.values())),
                        help="force the language instead of detecting it")


def gather(args):
    """Load the requested input and print any warnings. Returns None when nothing was readable."""
    use_stdin = args.stdin or "-" in args.paths
    paths = [p for p in args.paths if p != "-"]
    result = load_inputs(paths, use_stdin=use_stdin, paste=args.paste, language=args.language)
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
    findings = [f for f in analyze_many(inputs)
                if SEVERITY_RANK[f.severity] >= SEVERITY_RANK[args.min_severity]]
    if args.format == "json":
        print(format_json(findings, len(inputs)))
    else:
        print(format_text(findings, len(inputs), color=sys.stdout.isatty() and not args.no_color))
    if args.fail_on and any(SEVERITY_RANK[f.severity] >= SEVERITY_RANK[args.fail_on] for f in findings):
        return 1
    return 0


def cmd_train(args) -> int:
    try:
        from ml.train import train
    except ImportError as exc:
        print(f"error: {exc}. Install the ML dependency with: pip install -r requirements.txt",
              file=sys.stderr)
        return 2
    train(dataset=args.dataset, folds=args.folds)
    return 0


def cmd_predict(args) -> int:
    try:
        from ml.predict import format_predictions, score_inputs
    except ImportError as exc:
        print(f"error: {exc}. Install the ML dependency with: pip install -r requirements.txt",
              file=sys.stderr)
        return 2
    inputs = gather(args)
    if inputs is None:
        return 2
    try:
        predictions = score_inputs(inputs)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(format_predictions(predictions, args.threshold, show_all=args.show_all))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="main.py", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

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
    rules.set_defaults(func=cmd_rules)

    train = sub.add_parser("train", help="step 3: train the ML model")
    train.add_argument("--dataset", help="CSV with columns code,label (1 = insecure, 0 = secure); "
                                         "default is the built-in starter set")
    train.add_argument("--folds", type=int, default=5, help="cross-validation folds")
    train.set_defaults(func=cmd_train)

    predict = sub.add_parser("predict", help="step 3: score code with the trained ML model")
    add_input_args(predict)
    predict.add_argument("--threshold", type=float, default=0.5,
                         help="flag chunks whose insecure-probability is at least this (default 0.5)")
    predict.add_argument("--show-all", action="store_true", help="also list chunks below the threshold")
    predict.set_defaults(func=cmd_predict)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
