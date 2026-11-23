import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from main import build_parser, kilobytes_to_bytes, main


class ThresholdValidationTests(unittest.TestCase):
    # Input: non-finite thresholds must be rejected by argparse with a clear error.
    def test_rejects_nonfinite_thresholds(self):
        for text in ("nan", "NaN", "-nan", "inf", "-inf", "Infinity", "1e400"):
            err = io.StringIO()
            with redirect_stderr(err):
                with self.assertRaises(SystemExit) as ctx:
                    main(["predict", "--threshold", text])
            self.assertEqual(ctx.exception.code, 2, text)
            self.assertIn("error:", err.getvalue(), text)
            self.assertIn("--threshold", err.getvalue(), text)
            self.assertNotIn("Traceback", err.getvalue(), text)

    # Input: values outside the inclusive 0..1 range are rejected the same way.
    def test_rejects_out_of_range_thresholds(self):
        for text in ("-0.1", "1.5", "100", "-1"):
            err = io.StringIO()
            with redirect_stderr(err):
                with self.assertRaises(SystemExit) as ctx:
                    main(["predict", "--threshold", text])
            self.assertEqual(ctx.exception.code, 2, text)
            self.assertIn("error:", err.getvalue(), text)
            self.assertIn("--threshold", err.getvalue(), text)
            self.assertNotIn("Traceback", err.getvalue(), text)

    # Input: 0 and 1 are inclusive bounds and must still parse.
    def test_accepts_inclusive_bounds(self):
        parser = build_parser()
        self.assertEqual(parser.parse_args(["predict", "--threshold", "0"]).threshold, 0.0)
        self.assertEqual(parser.parse_args(["predict", "--threshold", "1"]).threshold, 1.0)

    # Input: the threshold keeps its previous default when the flag is omitted.
    def test_default_threshold_is_unchanged(self):
        self.assertEqual(build_parser().parse_args(["predict"]).threshold, 0.5)


class MaxKbTests(unittest.TestCase):
    # Input: non-finite values must be rejected (None) instead of raising at int(NaN)/int(inf).
    def test_nonfinite_values_do_not_crash(self):
        for text in ("nan", "NaN", "-nan", "inf", "-inf", "Infinity", "1e400"):
            self.assertIsNone(kilobytes_to_bytes(text), text)

    # Input: junk and overflowed text are rejected the same way as before the fix.
    def test_invalid_values_are_rejected(self):
        for text in ("", "abc", "1,5", " "):
            self.assertIsNone(kilobytes_to_bytes(text), text)

    # Input: ordinary numeric values still convert to bytes exactly as before.
    def test_ordinary_values_still_convert(self):
        self.assertEqual(kilobytes_to_bytes("1"), 1024)
        self.assertEqual(kilobytes_to_bytes("0.5"), 512)
        self.assertEqual(kilobytes_to_bytes("500"), 500 * 1024)
        self.assertEqual(kilobytes_to_bytes("0"), 0)

    # Input: the command exits with a status of 2 and an error line, never a traceback.
    def test_read_command_rejects_nan_without_traceback(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "a.py"
            path.write_text("print('hi')\n")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                status = main(["read", folder, "--max-kb", "nan"])
        self.assertEqual(status, 2)
        self.assertNotIn("Traceback", err.getvalue())
        self.assertIn("error: --max-kb", err.getvalue())
        self.assertEqual(out.getvalue(), "")

    # Input: the same command with a valid limit still reads the input normally.
    def test_read_command_accepts_ordinary_max_kb(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "a.py"
            path.write_text("print('hi')\n")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                status = main(["read", folder, "--max-kb", "10"])
        self.assertEqual(status, 0)
        self.assertIn("1 input(s) ready for analysis.", out.getvalue())


if __name__ == "__main__":
    unittest.main()
