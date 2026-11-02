from __future__ import annotations

from dataclasses import dataclass

from .models import CodeInput


@dataclass
class Chunk:
    start_line: int
    end_line: int
    text: str


def chunk_code(code: CodeInput, max_lines: int = 10, min_lines: int = 3) -> list[Chunk]:
    blocks: list[list[tuple[int, str]]] = []
    current: list[tuple[int, str]] = []
    for number, line in enumerate(code.lines, start=1):
        if line.strip():
            current.append((number, line))
        elif current:
            blocks.append(current)
            current = []
    if current:
        blocks.append(current)

    chunks: list[Chunk] = []
    pending: list[tuple[int, str]] = []

    def flush() -> None:
        nonlocal pending
        for start in range(0, len(pending), max_lines):
            piece = pending[start:start + max_lines]
            chunks.append(Chunk(piece[0][0], piece[-1][0], "\n".join(t for _, t in piece)))
        pending = []

    for block in blocks:
        pending.extend(block)
        if len(pending) >= min_lines:
            flush()
    if pending:
        flush()
    return chunks
