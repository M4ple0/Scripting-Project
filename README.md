# Secure Code Review - Phase 2 prototype

A local code-security checker that combines **rule-based analysis** with a **machine-learning
model** and uses no LLM, so nothing you scan leaves your machine and there is nothing to hallucinate.

Phase 2 delivers three components that work **separately**. Combining them (and the TUI) is Phase 3.

| Step | Command | What it does |
|------|---------|--------------|
| 1. Input | `python main.py read <paths>` | Takes files, folders, stdin or pasted code and shows how it was parsed |
| 2. Rules | `python main.py rules <paths>` | Runs the small rule scripts and reports findings with line, CWE, risk and fix |
| 3. ML | `python main.py train` / `predict <paths>` | Trains a classifier on a dataset and scores chunks of code |

## Quick start

```bash
pip install -r requirements.txt        # only the ML step needs this (scikit-learn)

python main.py read samples --chunks
python main.py rules samples/vulnerable_app.py
python main.py rules samples --min-severity high --format json
python main.py rules --list-rules

python main.py train
python main.py predict samples/vulnerable_app.py --show-all

cat file.py | python main.py rules -   # stdin
python main.py rules --paste           # type/paste code, finish with a line saying END

python -m unittest discover -s tests -t .
```

Useful flags: `--language` (force the language), `--fail-on high` (exit status 1 if something at
or above that severity is found - handy for CI), `--format json`.

## How it is laid out

```
main.py                 command line entry point
core/
  input_handler.py      step 1: files / folders / stdin / paste, language detection, warnings
  chunker.py            splits code into snippet-sized pieces for the ML model
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
ml/
  seed_data.py          starter dataset (120 hand-written snippets) + augmentation
  train.py, predict.py, model.py
samples/                deliberately vulnerable demo files and one safe file
tests/                  unittest suite
```

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

* Rules work **one line at a time**. A statement split over several lines can be missed, and data flow
  is not tracked, so `os.system(cmd)` is flagged even if `cmd` is safe. Expect some false positives
  and misses; this is a first layer, not a verdict.
* **The ML model is a pipeline demo, not a trustworthy detector yet.** It is trained on ~120 short
  snippets (about 330 after renaming variables). Cross-validation that keeps copies of the same snippet
  together scores around chance (accuracy ~0.5), meaning it does not yet generalise to code constructs it has
  not seen. It does separate the bundled vulnerable and safe samples, but those resemble its training data.
  Its value in Phase 2 is that the whole train -> save -> predict path works and is ready for real data.
* Chunks are cut at blank lines, which suits short snippets better than long functions.

## Next step for the ML component: real data

`python main.py train --dataset your.csv` accepts a CSV with columns `code,label` (label `1`/`insecure`
or `0`/`secure`); `python -m ml.seed_data` writes `ml/data/seed_dataset.csv` as a format example.
Candidate sources to research: the Juliet test suite and SARD (NIST), Devign, CVEfixes, Big-Vul, and the
vulnerable/fixed pairs in real CVE patches. When you add data, split train/test **by project or
commit**, not randomly - near-duplicate code in both halves makes the scores look better than they are.
Check each dataset's licence.

## Phase 3 ideas

Combine rules + ML into one scan with a single report, Textual dashboard, dependency/CVE lookup,
configurable policy files for internal security standards, and more languages.
