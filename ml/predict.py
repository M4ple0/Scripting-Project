"""Score code with the trained model."""
from __future__ import annotations

from dataclasses import dataclass

from core.chunker import chunk_code
from core.models import CodeInput

from .model import MODEL_PATH, load_model


# Holds one scored region of a file: line range, insecurity probability, and the code.
@dataclass
class Prediction:
    file: str
    start_line: int
    end_line: int
    probability: float   # estimated chance that the chunk is insecure
    snippet: str


# Split each input file into chunks, run them through the model, and collect the scores.
def score_inputs(inputs: list[CodeInput], model_path=MODEL_PATH) -> list[Prediction]:
    """Split every input into chunks and score each one."""
    pipeline = load_model(model_path)["pipeline"]
    # classes_ may be ordered [0, 1]; this picks the column for the insecure class
    insecure_column = list(pipeline.classes_).index(1)
    predictions: list[Prediction] = []
    # Chunk scoring: every file is cut into pieces first, then each piece gets one probability.
    for code in inputs:
        chunks = chunk_code(code)
        # Files that produce no chunks are skipped instead of scored as empty.
        if not chunks:
            continue
        # Select the insecure-class probability using the class index above.
        probabilities = pipeline.predict_proba([c.text for c in chunks])[:, insecure_column]
        # Pair each chunk with its probability so the report can point at exact lines.
        for chunk, probability in zip(chunks, probabilities):
            predictions.append(Prediction(code.name, chunk.start_line, chunk.end_line,
                                          float(probability), chunk.text))
    return predictions


# Turn raw scores into a readable report, flagging anything at or above the threshold.
def format_predictions(predictions: list[Prediction], threshold: float = 0.5,
                       show_all: bool = False) -> str:
    # Only chunks over the risk threshold count as flagged findings.
    flagged = [p for p in predictions if p.probability >= threshold]
    # --show-all keeps sub-threshold chunks in the listing, just marked "ok"
    shown = predictions if show_all else flagged
    # Start the report with a one-line summary of how many chunks were flagged.
    out = [f"ML review (threshold {threshold:.2f}): {len(flagged)} of {len(predictions)} "
           "chunk(s) flagged as likely insecure", ""]
    current_file = None
    # Sort by file then start line so the report reads in source order.
    for p in sorted(shown, key=lambda p: (p.file, p.start_line)):
        # Print a fresh file header whenever the file changes.
        if p.file != current_file:
            current_file = p.file
            out.append(p.file)
        marker = "FLAG" if p.probability >= threshold else "ok  "
        out.append(f"  lines {p.start_line}-{p.end_line:<5} {marker} risk {p.probability:.2f}")
        # Show a short preview of each chunk, truncated to three lines.
        preview = p.snippet.splitlines()
        for line in preview[:3]:
            out.append(f"      | {line.strip()[:100]}")
        if len(preview) > 3:
            out.append(f"      | ... (+{len(preview) - 3} more lines)")
    out.append("")
    # Remind the reader that ML output is a hint, not an automated verdict.
    out.append("The score is a statistical hint from a small model, not a verdict: "
               "review flagged chunks by hand.")
    return "\n".join(out)
