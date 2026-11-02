
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .models import CodeInput

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
SKIP_DIRS = {
    "node_modules", "__pycache__", "venv", "env", "dist", "build", "site-packages",
}
MAX_FILE_BYTES = 1_000_000
PASTE_END_MARKER = "END"


@dataclass
class LoadResult:
    inputs: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


def normalise_text(text: str) -> str:
    """Strip a BOM and make every line ending a plain newline."""
    if text.startswith("﻿"):
        text = text[1:]
    return text.replace("\r\n", "\n").replace("\r", "\n")


def detect_language(name: str, text: str = "") -> str:
    """Guess the language from the file extension, then a shebang, then the content."""
    extension = Path(name).suffix.lower()
    if extension in EXTENSION_LANGUAGES:
        return EXTENSION_LANGUAGES[extension]

    stripped = text.lstrip()
    first_line = stripped.splitlines()[0] if stripped else ""
    if first_line.startswith("#!"):
        if "python" in first_line:
            return "python"
        if "node" in first_line:
            return "javascript"
        if re.search(r"\b(?:ba|z)?sh\b", first_line):
            return "shell"
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
    return "unknown"


def from_text(text: str, name: str = "<snippet>", language: str | None = None) -> CodeInput:
    """Build a CodeInput from text that is already in memory."""
    text = normalise_text(text)
    return CodeInput(name=name, language=language or detect_language(name, text), text=text)


def read_file(path, result: LoadResult, language: str | None = None,
              max_bytes: int = MAX_FILE_BYTES) -> None:
    """Read one file into ``result``; any problem becomes a warning."""
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        result.warnings.append(f"{path}: cannot read ({exc.strerror or exc})")
        return
    if size > max_bytes:
        result.warnings.append(f"{path}: skipped, larger than {max_bytes:,} bytes")
        return
    try:
        raw = path.read_bytes()
    except OSError as exc:
        result.warnings.append(f"{path}: cannot read ({exc.strerror or exc})")
        return
    if b"\x00" in raw[:2048]:
        result.warnings.append(f"{path}: skipped, looks like a binary file")
        return
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
        result.warnings.append(f"{path}: not valid UTF-8, read as Latin-1")
    text = normalise_text(text)
    if not text.strip():
        result.warnings.append(f"{path}: skipped, file is empty")
        return
    result.inputs.append(from_text(text, name=str(path), language=language))


def walk_directory(root, result: LoadResult, language: str | None = None) -> None:
    """Read every supported source file below ``root`` (sorted, so output is stable)."""
    found = 0
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            if Path(name).suffix.lower() in EXTENSION_LANGUAGES:
                read_file(Path(current) / name, result, language)
                found += 1
    if found == 0:
        result.warnings.append(f"{root}: no supported source files found")


def read_stdin(result: LoadResult, language: str | None = None) -> None:
    if sys.stdin.isatty():
        print("Reading code from standard input... finish with Ctrl-D.", file=sys.stderr)
    text = normalise_text(sys.stdin.read())
    if not text.strip():
        result.warnings.append("<stdin>: nothing was received")
        return
    result.inputs.append(from_text(text, name="<stdin>", language=language))


def read_paste(result: LoadResult, language: str | None = None) -> None:
    """Interactive mode: the user pastes code and ends with a line saying END."""
    print(f"Paste your code below. Finish with a line containing only {PASTE_END_MARKER} "
          "(or Ctrl-D).", file=sys.stderr)
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == PASTE_END_MARKER:
            break
        lines.append(line)
    text = "\n".join(lines)
    if not text.strip():
        result.warnings.append("<pasted>: nothing was pasted")
        return
    result.inputs.append(from_text(text, name="<pasted>", language=language))


def load_inputs(paths=(), use_stdin: bool = False, paste: bool = False,
                language: str | None = None) -> LoadResult:
    result = LoadResult()
    for item in paths:
        path = Path(item)
        if path.is_dir():
            walk_directory(path, result, language)
        elif path.is_file():
            read_file(path, result, language)
        else:
            result.warnings.append(f"{item}: no such file or directory")
    if use_stdin:
        read_stdin(result, language)
    if paste:
        read_paste(result, language)
    return result
