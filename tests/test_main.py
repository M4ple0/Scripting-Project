import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from main import kilobytes_to_bytes, main


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
