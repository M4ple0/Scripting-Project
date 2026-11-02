"""Mechanics tests for the ML component.

These check that the pipeline runs end to end. They deliberately do NOT assert a
minimum accuracy: the starter dataset is too small for that to mean anything.
"""
import tempfile
import unittest
from pathlib import Path

try:
    import sklearn  # noqa: F401
    HAVE_SKLEARN = True
except ImportError:
    HAVE_SKLEARN = False

from core.input_handler import from_text


@unittest.skipUnless(HAVE_SKLEARN, "scikit-learn not installed")
class MLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ml.train import train
        cls.tmp = tempfile.TemporaryDirectory()
        cls.model_path = Path(cls.tmp.name) / "model.joblib"
        cls.metrics = train(model_path=cls.model_path, verbose=False)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_training_saves_model_and_reports_metrics(self):
        self.assertTrue(self.model_path.exists())
        self.assertEqual(set(self.metrics), {"accuracy", "precision", "recall", "f1"})
        for value in self.metrics.values():
            self.assertTrue(0.0 <= value <= 1.0)

    def test_scoring_returns_probabilities_for_every_chunk(self):
        from ml.predict import score_inputs
        code = from_text('a = 1\nb = 2\nos.system("ping " + host)\n\nx = 1 + 2\ny = x * 3\nz = y - 1',
                         language="python")
        predictions = score_inputs([code], model_path=self.model_path)
        self.assertEqual(len(predictions), 2)
        for p in predictions:
            self.assertTrue(0.0 <= p.probability <= 1.0)

    def test_training_seen_examples_rank_in_the_right_order(self):
        from ml.predict import score_inputs
        bad = from_text("gets(name);", language="c")
        good = from_text("fgets(name, sizeof(name), stdin);", language="c")
        bad_p = score_inputs([bad], model_path=self.model_path)[0].probability
        good_p = score_inputs([good], model_path=self.model_path)[0].probability
        self.assertGreater(bad_p, good_p)

    def test_missing_model_gives_helpful_error(self):
        from ml.model import load_model
        with self.assertRaises(FileNotFoundError):
            load_model(Path(self.tmp.name) / "nope.joblib")

    def test_csv_dataset_loading_and_label_validation(self):
        from ml.train import load_dataset
        path = Path(self.tmp.name) / "d.csv"
        path.write_text("code,label\nx = 1,secure\neval(y),insecure\n")
        codes, labels, groups = load_dataset(path)
        self.assertEqual(labels, [0, 1])
        self.assertIsNone(groups)
        path.write_text("code,label\nx = 1,maybe\n")
        with self.assertRaises(ValueError):
            load_dataset(path)


if __name__ == "__main__":
    unittest.main()
