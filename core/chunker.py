from __future__ import annotations

from dataclasses import dataclass

from .models import CodeInput


# A code snippet with its original start and end line numbers.
@dataclass
class Chunk:
    start_line: int
    end_line: int
    text: str


# Split the code into small line-chunks so each piece can be scanned on its own.
def chunk_code(code: CodeInput, max_lines: int = 10, min_lines: int = 3) -> list[Chunk]:
    # Group non-blank runs first so a chunk never starts mid-gap between functions
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
        # Pack accumulated lines into max_lines pieces, tracking real line numbers
        nonlocal pending
        for start in range(0, len(pending), max_lines):
            piece = pending[start:start + max_lines]
            chunks.append(Chunk(piece[0][0], piece[-1][0], "\n".join(t for _, t in piece)))
        pending = []

    # Add blocks until we have at least min_lines, then flush them into chunks.
    for block in blocks:
        pending.extend(block)
        if len(pending) >= min_lines:
            flush()
    # Flush whatever is left over so no lines are dropped.
    if pending:
        flush()
    return chunks
