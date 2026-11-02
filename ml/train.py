"""Train and evaluate the insecure-code classifier."""
from __future__ import annotations

import csv
from pathlib import Path

from .model import MODEL_PATH, build_pipeline, save_model

_TRUE = {"1", "insecure", "vulnerable", "bad", "true"}
_FALSE = {"0", "secure", "safe", "good", "false"}


def load_dataset(path=None):
    """Return (codes, labels, groups).

    ``path`` is a CSV with columns code,label (language optional). Without a path the
    built-in starter set is used, expanded with renamed copies; ``groups`` then tells
    which original snippet each row came from (None for a CSV you supply).
    """
    if path is None:
        from .seed_data import augment
        rows = augment()
        return [r[0] for r in rows], [r[1] for r in rows], [r[2] for r in rows]

    codes, labels = [], []
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not {"code", "label"} <= set(reader.fieldnames):
            raise ValueError(f"{path}: the CSV needs 'code' and 'label' columns")
        for row_number, row in enumerate(reader, start=2):
            value = (row["label"] or "").strip().lower()
            if value in _TRUE:
                labels.append(1)
            elif value in _FALSE:
                labels.append(0)
            else:
                raise ValueError(f"{path}, row {row_number}: unknown label {row['label']!r}")
            codes.append(row["code"])
    return codes, labels, None


def train(dataset=None, folds: int = 5, model_path: Path = MODEL_PATH, verbose: bool = True) -> dict:
    import numpy as np
    from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold, cross_validate

    codes, labels, groups = load_dataset(dataset)
    insecure, secure = sum(labels), len(labels) - sum(labels)
    if min(insecure, secure) < 2:
        raise ValueError("the dataset needs at least 2 examples of each class")
    folds = max(2, min(folds, insecure, secure))

    if groups is not None:
        # Every renamed copy of a snippet stays on one side of the split, so the score
        # measures performance on code constructs the model has not seen.
        splitter = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=42)
    else:
        splitter = StratifiedKFold(n_splits=folds, shuffle=True, random_state=42)
    scores = cross_validate(
        build_pipeline(), codes, labels, groups=groups, cv=splitter,
        scoring=("accuracy", "precision", "recall", "f1"),
    )
    metrics = {name: float(np.mean(scores[f"test_{name}"]))
               for name in ("accuracy", "precision", "recall", "f1")}

    pipeline = build_pipeline().fit(codes, labels)
    save_model(pipeline, {"examples": len(labels), "insecure": insecure, "secure": secure,
                          "cv_folds": folds, **metrics}, model_path)

    if verbose:
        print(f"Dataset: {len(labels)} snippets ({insecure} insecure, {secure} secure)")
        kind = "grouped " if groups is not None else ""
        print(f"{folds}-fold {kind}cross-validation (scores on unseen snippets):")
        for name, value in metrics.items():
            print(f"  {name:<10} {value:.3f}")
        coefficients = pipeline.named_steps["clf"].coef_[0]
        names = pipeline.named_steps["tfidf"].get_feature_names_out()
        top = np.argsort(coefficients)[-10:][::-1]
        print("Strongest 'insecure' indicators: " + " | ".join(names[i] for i in top))
        print(f"Model saved to {model_path}")
        if dataset is None:
            print("Note: this is the tiny starter dataset - treat the scores as a smoke test, "
                  "not as real-world accuracy.")
    return metrics
