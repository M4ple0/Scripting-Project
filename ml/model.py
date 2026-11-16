"""The model definition and saving/loading, shared by training and prediction."""
from __future__ import annotations

from pathlib import Path

MODEL_PATH = Path(__file__).with_name("model.joblib")

# Identifiers, numbers, and every punctuation character as its own token, so operators
# such as + % ( and quote characters become features alongside the function names.
TOKEN_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]"


# Assemble the reusable model: a text vectorizer feeding a logistic-regression classifier.
def build_pipeline():
    # imported lazily so commands like `read`/`rules` run without scikit-learn
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    # TF-IDF: each snippet becomes a vector of "how often does this token appear here,
    # discounted by how common it is across all snippets", so rare tokens weigh more.
    # Logistic regression then learns one weight per token: positive pushes the
    # prediction toward "insecure", negative toward "secure".
    return Pipeline([
        ("tfidf", TfidfVectorizer(token_pattern=TOKEN_PATTERN, lowercase=False,
                                  ngram_range=(1, 3), sublinear_tf=True)),
        ("clf", LogisticRegression(C=10.0, max_iter=2000, class_weight="balanced")),
    ])


# Write the trained pipeline plus its metadata to disk as a single joblib file.
def save_model(pipeline, metadata: dict, path: Path = MODEL_PATH) -> None:
    import joblib
    joblib.dump({"pipeline": pipeline, "meta": metadata}, path)


# Read the saved model back from disk, or explain how to train one if it's missing.
def load_model(path: Path = MODEL_PATH) -> dict:
    import joblib
    path = Path(path)
    # Friendly error for first-time users who run predict before train.
    if not path.exists():
        raise FileNotFoundError(
            f"no trained model at {path}. Train one first with: python main.py train")
    return joblib.load(path)
