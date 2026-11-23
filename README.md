# Secure Code Review - Phase 2 prototype

A local code-security checker that combines rule-based and AST analysis with no external services,
so nothing you scan leaves your machine.

The command-line scanner reads source files, runs security rules, and produces text or JSON reports.

| Step | Command | What it does |
|------|---------|--------------|
| 1. Input | `python main.py read <paths>` | Takes files, folders, stdin or pasted code and shows how it was parsed |
| 2. Rules | `python main.py rules <paths>` | Runs the small rule scripts and reports findings with line, CWE, risk and fix |

## Quick start

```bash
python main.py read samples --chunks
python main.py rules samples/vulnerable_app.py
python main.py rules samples --min-severity high --format json
python main.py rules --list-rules

cat file.py | python main.py rules -   # stdin
python main.py rules --paste           # type/paste code, finish with a line saying END

```

Useful flags: `--language` (force the language), `--fail-on high` (exit status 1 if something at
or above that severity is found - handy for CI), `--format json`, `--output report.txt` (write the
report to a file), `--max-kb 500` (skip larger files; the default can also be set with the
`SECREVIEW_MAX_BYTES` environment variable). `--version` shows the version and Python version.

Every text report ends with a **risk score** (findings weighted by severity: info 0, low 1,
medium 3, high 7, critical 10) and the average per input.

## How it is laid out

```
main.py                 command line entry point
core/
  input_handler.py      step 1: files / folders / stdin / paste, language detection, warnings
  chunker.py            splits code into review-sized chunks
  models.py, report.py  shared data types, text and JSON output
rules/
  engine.py             finds every rule script automatically and runs it
  base.py               Rule type, comment skipping, # nosec suppression
  hardcoded_secrets.py  passwords, API keys, tokens, private keys (+ entropy check)
  sql_injection.py      string-built SQL
  command_injection.py  shell commands built from variables
  unsafe_functions.py   eval/exec, pickle/yaml, banned C functions, XSS sinks, path traversal
  weak_crypto.py        MD5/SHA-1, DES/RC4/ECB, predictable randomness, old TLS
  insecure_config.py    debug mode, disabled TLS checks, wildcard CORS, loose permissions
  error_handling.py     bare/empty except, no timeouts, unchecked malloc, assert as a check
  ast_analysis.py       Python only: parses the code into a syntax tree and follows untrusted input
                        (input(), sys.argv, os.environ, Flask request data, route parameters) into
                        dangerous calls (shell, eval, SQL, file paths, pickle/yaml, URLs, templates)
samples/                deliberately vulnerable demo files and one safe file
```

### How the AST analysis works

`rules/ast_analysis.py` parses a Python file with the `ast` module and walks the tree in order.
It keeps a table of which variables hold **untrusted data** (a "taint") and follows that data through
assignments, f-strings, concatenation, `.format()`, loops, tuple unpacking and string methods.
`int()`, `float()`, `shlex.quote()`, `html.escape()` and similar calls clear the taint. A finding
is reported only when tainted data really reaches a dangerous call, and its message shows the flow,
for example `sys.argv (line 36) -> subprocess.run(shell=True)`.

It also summarises each function you define, so data passed to a helper that sends its argument
to a dangerous call (or returns it) is followed across function calls. Import aliases such as
`import subprocess as sp` are resolved, statements split over several lines are handled, and
`# nosec` still silences a line. Anything that does not parse as Python is skipped quietly.

### Adding a rule

Add a `Rule(...)` to an existing script, or drop a new `.py` file in `rules/` that defines
`NAME`, `DESCRIPTION`, `RULES` and `check(code)`. The engine picks it up automatically.
Each rule carries its severity, CWE id, an explanation of the risk and a recommended fix.
Append `# nosec` to a line to silence it deliberately.

### About CVEs

A CVE identifies a flaw in one specific product and version, so a pattern scanner cannot honestly
attach a CVE to "this line looks like SQL injection". Findings therefore carry a **CWE** (the weakness
class). Real CVE output belongs to dependency checking - comparing `requirements.txt` / `package.json`
versions against a vulnerability database such as OSV - which is a good Phase 3 addition.

## Limitations (read before trusting the output)

* The regex rules work **one line at a time**. A statement split over several lines can be missed, and
  data flow is not tracked, so `os.system(cmd)` is flagged even if `cmd` is safe. The AST analysis
  fixes this for Python (it only reports real flows), but the regex rules still run beside it, so
  expect some false positives and misses; this is a first layer, not a verdict.
* The AST analysis is Python only, works one file at a time, ignores values stored on `self`,
  and treats ordinary function parameters as trusted (only route parameters count as untrusted).
* Chunks are cut at blank lines, which suits short snippets better than long functions.

## Phase 3 ideas

Combine the rule and AST engines into a Textual dashboard, add dependency/CVE lookup,
configurable policy files for internal security standards, and more languages.
