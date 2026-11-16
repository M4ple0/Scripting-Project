import builtins
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.chunker import chunk_code
from core.input_handler import detect_language, from_text, load_inputs


class InputTests(unittest.TestCase):
    # Group: each test gets a fresh temporary folder to write sample files into.
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    # Group: delete the temporary folder when the test finishes.
    def tearDown(self):
        self.tmp.cleanup()

    # A single .py file is loaded once and its language is guessed from the extension.
    def test_reads_single_file_and_detects_language(self):
        (self.root / "a.py").write_text("print('hi')\n")
        result = load_inputs([self.root / "a.py"])
        self.assertEqual(len(result.inputs), 1)
        self.assertEqual(result.inputs[0].language, "python")

    # Input: one good JS file alongside junk that must be skipped: a .txt file and a node_modules folder.
    def test_directory_walk_skips_junk_and_unsupported_files(self):
        (self.root / "keep.js").write_text("let a = 1;\n")
        (self.root / "notes.txt").write_text("not code\n")
        (self.root / "node_modules").mkdir()
        (self.root / "node_modules" / "lib.js").write_text("let b = 2;\n")
        names = [Path(i.name).name for i in load_inputs([self.root]).inputs]
        self.assertEqual(names, ["keep.js"])

    # Input: a binary file, a whitespace-only file and a missing file all become warnings instead of crashing.
    def test_problem_files_become_warnings_not_crashes(self):
        (self.root / "blob.py").write_bytes(b"\x00\x01\x02binary")
        (self.root / "empty.py").write_text("   \n")
        result = load_inputs([self.root / "blob.py", self.root / "empty.py", self.root / "missing.py"])
        self.assertEqual(result.inputs, [])
        self.assertEqual(len(result.warnings), 3)

    # Input with a BOM and Windows line endings comes back as plain text with \n endings.
    def test_crlf_and_bom_are_normalised(self):
        code = from_text("﻿x = 1\r\ny = 2\r\n", language="python")
        self.assertEqual(code.text, "x = 1\ny = 2\n")

    # A latin-1 encoded file still loads, but reports a warning about the encoding.
    def test_latin1_file_is_read_with_warning(self):
        (self.root / "old.py").write_bytes("name = 'caf\xe9'\n".encode("latin-1"))
        result = load_inputs([self.root / "old.py"])
        self.assertEqual(len(result.inputs), 1)
        self.assertTrue(result.warnings)

    # Input: fake stdin holds the code; assertions check the name and the forced language.
    def test_stdin_input(self):
        with mock.patch("sys.stdin", io.StringIO("int main(){return 0;}\n")):
            result = load_inputs(use_stdin=True, language="c")
        self.assertEqual(result.inputs[0].name, "<stdin>")
        self.assertEqual(result.inputs[0].language, "c")

    # Input: typed lines are collected until the END marker, and anything after it is ignored.
    def test_paste_input_stops_at_end_marker(self):
        typed = iter(["x = 1", "y = 2", "END", "ignored"])
        with mock.patch.object(builtins, "input", lambda: next(typed)):
            result = load_inputs(paste=True)
        self.assertEqual(result.inputs[0].text, "x = 1\ny = 2")

    # With no file extension, the language is guessed from the code's own content instead.
    def test_language_detection_without_extension(self):
        self.assertEqual(detect_language("snippet", "<?php echo 1;"), "php")
        self.assertEqual(detect_language("snippet", "#include <stdio.h>\n"), "c")
        self.assertEqual(detect_language("snippet", "def f(x):\n    return x\n"), "python")
        self.assertEqual(detect_language("snippet", "const a = () => 1;"), "javascript")

    # Setup: 29 lines split into 10-line chunks starting at lines 1, 11 and 21 with no line lost at the end.
    def test_chunker_covers_all_code_lines_in_order(self):
        text = "\n".join(f"line{i}" for i in range(1, 30))
        chunks = chunk_code(from_text(text, language="python"), max_lines=10)
        self.assertEqual([c.start_line for c in chunks], [1, 11, 21])
        self.assertEqual(chunks[-1].end_line, 29)


if __name__ == "__main__":
    unittest.main()
