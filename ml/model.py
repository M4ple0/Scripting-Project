"""The model definition and saving/loading, shared by training and prediction."""
from __future__ import annotations

from pathlib import Path

MODEL_PATH = Path(__file__).with_name("model.joblib")

# Identifiers, numbers, and every punctuation character as its own token, so operators
# such as + % ( and quote characters become features alongside the function names.
TOKEN_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]"


def build_pipeline():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    return Pipeline([
        ("tfidf", TfidfVectorizer(token_pattern=TOKEN_PATTERN, lowercase=False,
                                  ngram_range=(1, 3), sublinear_tf=True)),
        ("clf", LogisticRegression(C=10.0, max_iter=2000, class_weight="balanced")),
    ])


def save_model(pipeline, metadata: dict, path: Path = MODEL_PATH) -> None:
    import joblib
    joblib.dump({"pipeline": pipeline, "meta": metadata}, path)


def load_model(path: Path = MODEL_PATH) -> dict:
    import joblib
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(
            f"no trained model at {path}. Train one first with: python main.py train")
    return joblib.load(path)
