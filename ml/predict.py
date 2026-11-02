"""Score code with the trained model."""
from __future__ import annotations

from dataclasses import dataclass

from core.chunker import chunk_code
from core.models import CodeInput

from .model import MODEL_PATH, load_model


@dataclass
class Prediction:
    file: str
    start_line: int
    end_line: int
    probability: float   # estimated chance that the chunk is insecure
    snippet: str


def score_inputs(inputs: list[CodeInput], model_path=MODEL_PATH) -> list[Prediction]:
    """Split every input into chunks and score each one."""
    pipeline = load_model(model_path)["pipeline"]
    insecure_column = list(pipeline.classes_).index(1)
    predictions: list[Prediction] = []
    for code in inputs:
        chunks = chunk_code(code)
        if not chunks:
            continue
        probabilities = pipeline.predict_proba([c.text for c in chunks])[:, insecure_column]
        for chunk, probability in zip(chunks, probabilities):
            predictions.append(Prediction(code.name, chunk.start_line, chunk.end_line,
                                          float(probability), chunk.text))
    return predictions


def format_predictions(predictions: list[Prediction], threshold: float = 0.5,
                       show_all: bool = False) -> str:
    flagged = [p for p in predictions if p.probability >= threshold]
    shown = predictions if show_all else flagged
    out = [f"ML review (threshold {threshold:.2f}): {len(flagged)} of {len(predictions)} "
           "chunk(s) flagged as likely insecure", ""]
    current_file = None
    for p in sorted(shown, key=lambda p: (p.file, p.start_line)):
        if p.file != current_file:
            current_file = p.file
            out.append(p.file)
        marker = "FLAG" if p.probability >= threshold else "ok  "
        out.append(f"  lines {p.start_line}-{p.end_line:<5} {marker} risk {p.probability:.2f}")
        preview = p.snippet.splitlines()
        for line in preview[:3]:
            out.append(f"      | {line.strip()[:100]}")
        if len(preview) > 3:
            out.append(f"      | ... (+{len(preview) - 3} more lines)")
    out.append("")
    out.append("The score is a statistical hint from a small model, not a verdict: "
               "review flagged chunks by hand.")
    return "\n".join(out)
