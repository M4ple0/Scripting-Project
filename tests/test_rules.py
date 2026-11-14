import unittest
from pathlib import Path

from core.input_handler import from_text, load_inputs
from rules.engine import analyze, list_rules, load_rule_modules

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def ids(text, language):
    return {f.rule_id for f in analyze(from_text(text, language=language))}


class RuleTests(unittest.TestCase):
    def test_every_rule_script_is_discovered(self):
        names = {m.NAME for m in load_rule_modules()}
        self.assertEqual(names, {"hardcoded_secrets", "sql_injection", "command_injection",
                                 "unsafe_functions", "weak_crypto", "insecure_config",
                                 "error_handling", "ast_analysis"})
        self.assertGreaterEqual(len(list_rules()), 40)

    def test_sql_injection_detected_and_parameterised_query_is_clean(self):
        self.assertIn("SQL001", ids('cursor.execute(f"SELECT * FROM u WHERE id = {uid}")', "python"))
        self.assertIn("SQL002", ids('q = "SELECT * FROM u WHERE n = \'" + name + "\'"', "python"))
        self.assertEqual(ids('cursor.execute("SELECT * FROM u WHERE id = %s", (uid,))', "python"), set())

    def test_command_injection(self):
        self.assertIn("CMD002", ids('subprocess.call("ls " + d, shell=True)', "python"))
        self.assertIn("CMD001", ids('os.system("ping " + host)', "python"))
        self.assertEqual(ids('os.system("clear")', "python"), set())
        self.assertEqual(ids('subprocess.run(["ls", d])', "python"), set())

    def test_secrets(self):
        self.assertIn("SEC001", ids('password = "Sup3rS3cret!"', "python"))
        self.assertEqual(ids('password = os.environ["PW"]', "python"), set())
        self.assertEqual(ids('password = "changeme"', "python"), set())
        self.assertIn("SEC003", ids('key = "AKIAIOSFODNN7EXAMPLE"', "python"))

    def test_weak_crypto(self):
        self.assertIn("CRY001", ids("h = hashlib.md5(x).hexdigest()", "python"))
        self.assertIn("CRY002", ids("c = AES.new(k, AES.MODE_ECB)", "python"))
        self.assertEqual(ids("h = hashlib.sha256(x).hexdigest()", "python"), set())

    def test_c_banned_functions(self):
        found = ids("gets(buf);\nstrcpy(a, b);\nprintf(user);", "c")
        self.assertTrue({"UNS005", "UNS006", "UNS008"} <= found)
        self.assertEqual(ids('snprintf(buf, sizeof(buf), "%s", x);', "c"), set())

    def test_error_handling(self):
        self.assertIn("ERR001", ids("try:\n    f()\nexcept:\n    log()", "python"))
        self.assertIn("ERR002", ids("try:\n    f()\nexcept ValueError:\n    pass", "python"))
        self.assertIn("ERR005", ids("p = malloc(10);\np[0] = 1;", "c"))
        self.assertEqual(ids("p = malloc(10);\nif (p == NULL) return -1;", "c"), set())
        self.assertIn("ERR004", ids("r = requests.get(url)", "python"))
        self.assertEqual(ids("r = requests.get(url, timeout=5)", "python"), set())

    def test_comments_and_suppression_are_ignored(self):
        self.assertEqual(ids("# eval(x)", "python"), set())
        self.assertEqual(ids('os.system("ping " + h)  # nosec', "python"), set())

    def test_language_specific_rules_do_not_leak_across_languages(self):
        self.assertEqual(ids("eval(x)", "c"), set())

    def test_unknown_language_gets_every_rule(self):
        # eval() is a code-execution rule in Python, JavaScript and PHP; with no known
        # language all of them apply and the dedupe keeps the most severe one.
        found = {f.rule_id for f in analyze(from_text("eval(x)", language="unknown"))}
        self.assertTrue(found & {"UNS001", "UNS002", "UNS011"})

    def test_one_finding_per_line_and_weakness(self):
        findings = analyze(from_text('API_KEY = "sk_live_FAKEFAKEFAKEFAKEFAKE1234"', language="python"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")

    def test_vulnerable_samples_are_flagged_and_safe_sample_is_clean(self):
        bad = analyze(load_inputs([SAMPLES / "vulnerable_app.py"]).inputs[0])
        self.assertGreaterEqual(len(bad), 15)
        for name in ("vulnerable.js", "vulnerable.c", "vulnerable.php"):
            self.assertGreaterEqual(len(analyze(load_inputs([SAMPLES / name]).inputs[0])), 5, name)
        self.assertEqual(analyze(load_inputs([SAMPLES / "safe_app.py"]).inputs[0]), [])


if __name__ == "__main__":
    unittest.main()
