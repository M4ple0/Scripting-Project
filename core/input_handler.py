
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .models import CodeInput

# Map file extensions to the language name used when scanning.
EXTENSION_LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".php": "php",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".sh": "shell",
}
# Directory names we never look inside (deps, caches, build output).
SKIP_DIRS = {
    "node_modules", "__pycache__", "venv", "env", "dist", "build", "site-packages",
}
# Default size cap: files larger than this are skipped to keep loading fast and safe.
DEFAULT_MAX_FILE_BYTES = 1_000_000
MAX_BYTES_ENV_VAR = "SECREVIEW_MAX_BYTES"
# The line that signals the end of an interactive code paste.
PASTE_END_MARKER = "END"


# Collects the code inputs we loaded plus any warnings about problems.
@dataclass
class LoadResult:
    inputs: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


def configured_max_bytes() -> int:
    raw = os.environ.get(MAX_BYTES_ENV_VAR, "")
    try:
        limit = int(raw)
    except ValueError:
        return DEFAULT_MAX_FILE_BYTES
    return limit if limit > 0 else DEFAULT_MAX_FILE_BYTES


MAX_FILE_BYTES = configured_max_bytes()


def normalise_text(text: str) -> str:
    """Strip a BOM and make every line ending a plain newline."""
    # Drop a leading byte-order mark so it never leaks into the code.
    if text.startswith("﻿"):
        text = text[1:]
    # Fold Windows and old-Mac line endings into plain newlines.
    return text.replace("\r\n", "\n").replace("\r", "\n")


def detect_language(name: str, text: str = "") -> str:
    """Guess the language from the file extension, then a shebang, then the content."""
    # The file extension is checked first.
    extension = Path(name).suffix.lower()
    if extension in EXTENSION_LANGUAGES:
        return EXTENSION_LANGUAGES[extension]

    # No usable extension, so fall back to the first non-blank line.
    stripped = text.lstrip()
    first_line = stripped.splitlines()[0] if stripped else ""
    # A shebang names the interpreter directly when the name tells us nothing.
    if first_line.startswith("#!"):
        if "python" in first_line:
            return "python"
        if "node" in first_line:
            return "javascript"
        if re.search(r"\b(?:ba|z)?sh\b", first_line):
            return "shell"
    # Otherwise scan the content for markers that suggest certain languages.
    if "<?php" in text[:300]:
        return "php"
    if re.search(r"^\s*#\s*include\s*[<\"]", text, re.M):
        return "c"
    if re.search(r"^\s*(?:async\s+)?def\s+\w+\s*\(.*\)\s*(?:->.*)?:", text, re.M):
        return "python"
    if re.search(r"\b(?:const|let|var|function)\b|=>", text):
        return "javascript"
    if re.search(r"^\s*(?:import|from)\s+\w+", text, re.M) and ";" not in text:
        return "python"
    # Admit defeat rather than guessing a language we are not sure about.
    return "unknown"


def from_text(text: str, name: str = "<snippet>", language: str | None = None) -> CodeInput:
    """Build a CodeInput from text that is already in memory."""
    # Normalize line endings and any BOM before the text is stored.
    text = normalise_text(text)
    # An explicit language wins; otherwise detect one from the name and content.
    return CodeInput(name=name, language=language or detect_language(name, text), text=text)


def read_file(path, result: LoadResult, language: str | None = None,
              max_bytes: int | None = None) -> None:
    """Read one file into ``result``; any problem becomes a warning."""
    path = Path(path)
    max_bytes = max_bytes or MAX_FILE_BYTES
    # Check the file exists and is stat-able before doing any real work.
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        result.warnings.append(f"{path}: cannot read ({exc.strerror or exc})")
        return
    # Skip oversized files to limit memory use.
    if size > max_bytes:
        result.warnings.append(f"{path}: skipped, larger than {max_bytes:,} bytes")
        return
    # Read raw bytes first so we can inspect the file before decoding it.
    try:
        raw = path.read_bytes()
    except OSError as exc:
        result.warnings.append(f"{path}: cannot read ({exc.strerror or exc})")
        return
    # Reject obvious binaries before any decoding is attempted.
    if b"\x00" in raw[:2048]:
        # a NUL in the header is the cheapest binary-file signal
        result.warnings.append(f"{path}: skipped, looks like a binary file")
        return
    # Decode as UTF-8 first, which also strips a BOM if present.
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        # latin-1 decodes any byte sequence, so the file is still scannable
        text = raw.decode("latin-1")
        result.warnings.append(f"{path}: not valid UTF-8, read as Latin-1")
    text = normalise_text(text)
    # Warn and skip files that hold nothing but whitespace.
    if not text.strip():
        result.warnings.append(f"{path}: skipped, file is empty")
        return
    # Store the parsed snippet so the caller can scan it later.
    result.inputs.append(from_text(text, name=str(path), language=language))


def walk_directory(root, result: LoadResult, language: str | None = None,
                   max_bytes: int | None = None) -> None:
    """Read every supported source file below ``root`` (sorted, so output is stable)."""
    found = 0

    # os.walk drops listing errors unless given an onerror hook; surface them as warnings.
    def record_walk_error(exc: OSError) -> None:
        path = exc.filename or root
        result.warnings.append(f"{path}: cannot list directory ({exc.strerror or exc})")

    # Walk the tree, skipping dependency, cache, and hidden directories.
    for current, dirs, files in os.walk(root, onerror=record_walk_error):
        # prune skipped/dotted dirs in place so os.walk never descends into them
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            # Only read files whose extension maps to a known language.
            if Path(name).suffix.lower() in EXTENSION_LANGUAGES:
                read_file(Path(current) / name, result, language, max_bytes)
                found += 1
    # Report it when the directory held no recognizable source files.
    if found == 0:
        result.warnings.append(f"{root}: no supported source files found")


# Read code piped in from standard input, e.g. `cat app.py | scanner`.
def read_stdin(result: LoadResult, language: str | None = None) -> None:
    # Tell interactive users how to finish feeding input.
    if sys.stdin.isatty():
        print("Reading code from standard input... finish with Ctrl-D.", file=sys.stderr)
    # Read everything piped in at once, then normalize it.
    try:
        raw_text = sys.stdin.read()
    except UnicodeDecodeError:
        result.warnings.append("<stdin>: could not decode input as text")
        return
    text = normalise_text(raw_text)
    # Warn when stdin produced no code at all.
    if not text.strip():
        result.warnings.append("<stdin>: nothing was received")
        return
    # Store the snippet under a recognizable <stdin> name.
    result.inputs.append(from_text(text, name="<stdin>", language=language))


def read_paste(result: LoadResult, language: str | None = None) -> None:
    """Interactive mode: the user pastes code and ends with a line saying END."""
    print(f"Paste your code below. Finish with a line containing only {PASTE_END_MARKER} "
          "(or Ctrl-D).", file=sys.stderr)
    lines = []
    # Collect lines until END or Ctrl-D signals the end of the paste.
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == PASTE_END_MARKER:
            break
        lines.append(line)
    text = "\n".join(lines)
    # Warn when the paste contained no code.
    if not text.strip():
        result.warnings.append("<pasted>: nothing was pasted")
        return
    # Store the pasted snippet under a <pasted> name.
    result.inputs.append(from_text(text, name="<pasted>", language=language))


# Turn the given paths and flags into a LoadResult of code inputs.
def load_inputs(paths=(), use_stdin: bool = False, paste: bool = False,
                language: str | None = None, max_bytes: int | None = None) -> LoadResult:
    result = LoadResult()
    # Each path becomes either a recursive walk or a single file read.
    for item in paths:
        if os.path.isdir(item):
            walk_directory(item, result, language, max_bytes)
        elif os.path.isfile(item):
            read_file(item, result, language, max_bytes)
        else:
            # Missing paths become warnings instead of hard failures.
            result.warnings.append(f"{item}: no such file or directory")
    # Optionally fold in piped stdin and an interactive paste.
    if use_stdin:
        read_stdin(result, language)
    if paste:
        read_paste(result, language)
    # Return everything collected so the caller sees inputs and warnings together.
    return result
