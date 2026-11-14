import unittest

from core.input_handler import from_text
from rules import ast_analysis


def found(text, language="python"):
    return {f.rule_id for f in ast_analysis.check(from_text(text, language=language))}


class TaintTests(unittest.TestCase):
    def test_input_flowing_into_os_system_is_flagged(self):
        self.assertEqual(found('cmd = input()\nos.system("ls " + cmd)'), {"AST001"})

    def test_constant_command_is_not_flagged(self):
        self.assertEqual(found('os.system("clear")'), set())
        self.assertEqual(found('host = "localhost"\nos.system("ping " + host)'), set())

    def test_casting_and_escaping_clean_the_data(self):
        self.assertEqual(found('n = int(input())\nos.system("sleep " + str(n))'), set())
        self.assertEqual(found('import shlex\nx = input()\nos.system("ls " + shlex.quote(x))'), set())

    def test_data_is_followed_through_assignments_and_fstrings(self):
        code = "import sys\na = sys.argv[1]\nb = a.strip()\nc = f'ls {b}'\nos.system(c)"
        self.assertEqual(found(code), {"AST001"})

    def test_reassigning_a_clean_value_removes_the_taint(self):
        self.assertEqual(found('x = input()\nx = "safe"\nos.system("ls " + x)'), set())

    def test_multi_line_call_is_found(self):
        code = 'import subprocess\nx = input()\nsubprocess.run(\n    "ls " + x,\n    shell=True,\n)'
        findings = ast_analysis.check(from_text(code, language="python"))
        self.assertEqual([f.rule_id for f in findings], ["AST001"])
        self.assertEqual(findings[0].line, 3)

    def test_list_arguments_without_shell_are_not_flagged(self):
        self.assertEqual(found('import subprocess\nx = input()\nsubprocess.run(["ls", x])'), set())

    def test_eval_is_critical(self):
        findings = ast_analysis.check(from_text("import sys\neval(sys.argv[1])", language="python"))
        self.assertEqual([(f.rule_id, f.severity) for f in findings], [("AST002", "critical")])

    def test_sql_built_from_input_is_flagged_but_parameterised_is_clean(self):
        bad = 'name = input()\nq = "SELECT * FROM u WHERE n = \'" + name + "\'"\ncur.execute(q)'
        good = 'name = input()\ncur.execute("SELECT * FROM u WHERE n = ?", (name,))'
        self.assertEqual(found(bad), {"AST003"})
        self.assertEqual(found(good), set())

    def test_flask_request_data_and_route_parameters_are_sources(self):
        self.assertEqual(found("from flask import request\nopen(request.args['f'])"), {"AST004"})
        code = "@app.route('/f/<name>')\ndef f(name):\n    return open(name).read()"
        self.assertEqual(found(code), {"AST004"})

    def test_ordinary_function_parameters_are_not_assumed_untrusted(self):
        self.assertEqual(found("def f(name):\n    return open(name).read()"), set())

    def test_helper_function_chain_is_followed(self):
        code = (
            "def run(command):\n    return os.popen(command).read()\n"
            "def wrapper(text):\n    return run('echo ' + text)\n"
            "wrapper(input())"
        )
        findings = ast_analysis.check(from_text(code, language="python"))
        self.assertEqual([f.rule_id for f in findings], ["AST001"])
        self.assertIn("through helper", findings[0].message)

    def test_value_returned_by_a_helper_stays_tainted(self):
        code = "def ask():\n    return input()\nos.system('ls ' + ask())"
        self.assertEqual(found(code), {"AST001"})

    def test_import_aliases_are_resolved(self):
        code = "import subprocess as sp\nfrom os import system as run\nx = input()\nsp.call(x, shell=True)\nrun(x)"
        self.assertEqual(len(ast_analysis.check(from_text(code, language="python"))), 2)

    def test_yaml_safe_loader_is_accepted(self):
        self.assertEqual(found("import yaml\nx = input()\nyaml.load(x, Loader=yaml.SafeLoader)"), set())
        self.assertEqual(found("import yaml\nx = input()\nyaml.load(x)"), {"AST005"})

    def test_nosec_suppresses_a_finding(self):
        self.assertEqual(found('x = input()\nos.system("ls " + x)  # nosec'), set())

    def test_broken_or_non_python_code_is_ignored(self):
        self.assertEqual(found("def broken(:\n    pass"), set())
        self.assertEqual(found('os.system(input())', language="c"), set())

    def test_finding_explains_the_flow(self):
        finding = ast_analysis.check(from_text("x = input()\nos.system(x)", language="python"))[0]
        self.assertIn("input() (line 1)", finding.message)
        self.assertEqual(finding.cwe, "CWE-78")


if __name__ == "__main__":
    unittest.main()
