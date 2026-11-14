from __future__ import annotations

import ast
from dataclasses import dataclass, field

from core.models import CodeInput, Finding

from .base import PY, SUPPRESSION, Rule

NAME = "ast_analysis"
DESCRIPTION = "Python syntax-tree analysis that follows untrusted input into dangerous calls"

RULES = [
    Rule(
        id="AST001", title="Untrusted data reaches a shell command (data-flow confirmed)",
        severity="high", cwe="CWE-78", languages=PY, pattern="",
        message="Input that a user controls is used to build a shell command.",
        recommendation="Use subprocess.run([...]) with a list of arguments, no shell, and validate the input.",
    ),
    Rule(
        id="AST002", title="Untrusted data reaches eval/exec/compile (data-flow confirmed)",
        severity="critical", cwe="CWE-95", languages=PY, pattern="",
        message="Input that a user controls is executed as Python code.",
        recommendation="Never evaluate user input. Use ast.literal_eval() or json.loads() for data.",
    ),
    Rule(
        id="AST003", title="Untrusted data reaches a SQL query (data-flow confirmed)",
        severity="high", cwe="CWE-89", languages=PY, pattern="",
        message="Input that a user controls becomes part of the SQL text.",
        recommendation="Use parameterised queries and pass the values separately from the SQL text.",
    ),
    Rule(
        id="AST004", title="Untrusted data reaches a file path (data-flow confirmed)",
        severity="medium", cwe="CWE-22", languages=PY, pattern="",
        message="Input that a user controls chooses which file is opened, sent or deleted.",
        recommendation="Resolve the path, confirm it stays inside an allowed directory, or use secure_filename().",
    ),
    Rule(
        id="AST005", title="Untrusted data reaches a deserialiser (data-flow confirmed)",
        severity="high", cwe="CWE-502", languages=PY, pattern="",
        message="Input that a user controls is deserialised with a format that can run code.",
        recommendation="Use json for data, or yaml.safe_load(). Never unpickle data you do not trust.",
    ),
    Rule(
        id="AST006", title="Untrusted data reaches an outgoing request URL (data-flow confirmed)",
        severity="medium", cwe="CWE-918", languages=PY, pattern="",
        message="Input that a user controls chooses the address the server connects to.",
        recommendation="Check the host against an allow-list before making the request.",
    ),
    Rule(
        id="AST007", title="Untrusted data reaches a template or HTML sink (data-flow confirmed)",
        severity="high", cwe="CWE-79", languages=PY, pattern="",
        message="Input that a user controls is rendered as a template or marked as safe HTML.",
        recommendation="Render fixed templates with escaped variables and avoid Markup() on user input.",
    ),
]
RULES_BY_ID = {rule.id: rule for rule in RULES}

SOURCE_CALLS = {"input", "raw_input", "sys.stdin.read", "sys.stdin.readline", "sys.stdin.readlines",
                "os.getenv", "os.environ.get"}
SOURCE_NAMES = {"sys.argv", "os.environ", "sys.stdin"}
REQUEST_ATTRS = {"args", "form", "values", "json", "data", "cookies", "headers", "files",
                 "view_args", "query_string", "GET", "POST", "COOKIES", "META", "body",
                 "get_json", "get_data"}
ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch"}

CLEANING_CALLS = {"int", "float", "bool", "len", "abs", "round", "quote", "escape", "basename",
                  "secure_filename", "isinstance", "hash"}
CLEANING_METHODS = {"isdigit", "isalpha", "isalnum", "isnumeric", "startswith", "endswith",
                    "count", "index", "find"}
PASSING_CALLS = {"str", "repr", "list", "tuple", "set", "dict", "sorted", "reversed", "bytes",
                 "bytearray", "format", "os.path.join", "os.path.abspath", "os.path.normpath",
                 "os.path.expanduser", "urllib.parse.unquote", "unquote", "base64.b64decode",
                 "json.loads"}
STRING_BUILDERS = {"format", "format_map", "join", "replace"}

SQL_METHODS = {"execute", "executemany", "executescript"}
SHELL_CALLS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output",
               "subprocess.check_call"}

SINKS = {
    "os.system": ("AST001", 0, ("command",)),
    "os.popen": ("AST001", 0, ("command",)),
    "subprocess.getoutput": ("AST001", 0, ("cmd",)),
    "subprocess.getstatusoutput": ("AST001", 0, ("cmd",)),
    "eval": ("AST002", 0, ("expression",)),
    "exec": ("AST002", 0, ("object",)),
    "compile": ("AST002", 0, ("source",)),
    "open": ("AST004", 0, ("file",)),
    "os.remove": ("AST004", 0, ("path",)),
    "os.unlink": ("AST004", 0, ("path",)),
    "shutil.rmtree": ("AST004", 0, ("path",)),
    "pickle.load": ("AST005", 0, ("file",)),
    "pickle.loads": ("AST005", 0, ("data",)),
    "marshal.loads": ("AST005", 0, ("data",)),
    "jsonpickle.decode": ("AST005", 0, ("string",)),
    "yaml.load": ("AST005", 0, ("stream",)),
    "yaml.unsafe_load": ("AST005", 0, ("stream",)),
    "requests.request": ("AST006", 1, ("url",)),
}
for _verb in ("get", "post", "put", "patch", "delete", "head", "options"):
    SINKS[f"requests.{_verb}"] = ("AST006", 0, ("url",))
    SINKS[f"httpx.{_verb}"] = ("AST006", 0, ("url",))

LAST_SEGMENT_SINKS = {
    "render_template_string": ("AST007", 0, ("source", "template_string")),
    "Markup": ("AST007", 0, ("markup",)),
    "send_file": ("AST004", 0, ("path_or_file",)),
    "send_from_directory": ("AST004", 1, ("path",)),
    "urlopen": ("AST006", 0, ("url",)),
}


@dataclass(frozen=True)
class Taint:
    origin: str
    line: int


@dataclass
class Summary:
    params: list
    kwonly: list = field(default_factory=list)
    sink_params: dict = field(default_factory=dict)
    return_params: set = field(default_factory=set)
    returns_source: Taint | None = None


def collect_aliases(tree: ast.AST) -> dict:
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".")[0]] = item.name if item.asname else item.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


class Analyzer(ast.NodeVisitor):
    def __init__(self, code: CodeInput, tree: ast.AST, summaries: dict, report: bool):
        self.code = code
        self.summaries = summaries
        self.report = report
        self.aliases = collect_aliases(tree)
        self.scopes: list[dict] = [{}]
        self.funcs: list[Summary] = []
        self.findings: list[Finding] = []
        self.seen: set = set()

    def resolve(self, node):
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        parts.append(self.aliases.get(node.id, node.id))
        name = ".".join(reversed(parts))
        if name.startswith("flask.request"):
            name = name[len("flask."):]
        return name

    def lookup(self, name):
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None

    def bind(self, target, taint):
        if isinstance(target, ast.Name):
            self.scopes[-1][target.id] = taint
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.bind(element, taint)
        elif isinstance(target, ast.Starred):
            self.bind(target.value, taint)
        elif isinstance(target, (ast.Attribute, ast.Subscript)) and taint:
            base = target.value
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                base = base.value
            if isinstance(base, ast.Name) and base.id not in ("self", "cls"):
                self.scopes[-1][base.id] = taint

    def first_taint(self, nodes):
        for node in nodes:
            taint = self.taint(node)
            if taint:
                return taint
        return None

    def source_for(self, node):
        name = self.resolve(node)
        if not name:
            return None
        if name in SOURCE_NAMES:
            return Taint(name, node.lineno)
        parts = name.split(".")
        if parts[0] == "request" and len(parts) > 1 and parts[1] in REQUEST_ATTRS:
            return Taint(f"request.{parts[1]}", node.lineno)
        return None

    def taint(self, node):
        if node is None or isinstance(node, ast.Constant):
            return None
        if isinstance(node, ast.Name):
            return self.lookup(node.id)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return self.source_for(node) or self.taint(node.value)
        if isinstance(node, ast.Call):
            return self.call_taint(node)
        if isinstance(node, ast.BinOp):
            return self.taint(node.left) or self.taint(node.right)
        if isinstance(node, ast.JoinedStr):
            return self.first_taint(node.values)
        if isinstance(node, (ast.FormattedValue, ast.Starred, ast.Await, ast.NamedExpr)):
            return self.taint(node.value)
        if isinstance(node, ast.IfExp):
            return self.taint(node.body) or self.taint(node.orelse)
        if isinstance(node, ast.BoolOp):
            return self.first_taint(node.values)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return self.first_taint(node.elts)
        if isinstance(node, ast.Dict):
            return self.first_taint([v for v in node.values if v is not None])
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            return self.first_taint([g.iter for g in node.generators])
        return None

    def local_function(self, node):
        func = node.func
        if isinstance(func, ast.Name) and func.id in self.summaries:
            return func.id, self.summaries[func.id]
        if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                and func.value.id in ("self", "cls") and func.attr in self.summaries):
            return func.attr, self.summaries[func.attr]
        return None

    def mapped_args(self, node, summary):
        pairs = [(summary.params[i], arg) for i, arg in enumerate(node.args) if i < len(summary.params)]
        pairs += [(kw.arg, kw.value) for kw in node.keywords if kw.arg]
        return pairs

    def call_taint(self, node):
        name = self.resolve(node.func)
        last = name.rsplit(".", 1)[-1] if name else None
        if last in CLEANING_CALLS:
            return None
        if name in SOURCE_CALLS:
            return Taint(f"{name}()", node.lineno)
        local = self.local_function(node)
        if local:
            _, summary = local
            for param, arg in self.mapped_args(node, summary):
                if param in summary.return_params:
                    taint = self.taint(arg)
                    if taint:
                        return taint
            return summary.returns_source
        arguments = list(node.args) + [kw.value for kw in node.keywords]
        if name in PASSING_CALLS:
            return self.first_taint(arguments)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in CLEANING_METHODS:
                return None
            taint = self.taint(node.func.value)
            if taint:
                return taint
            if node.func.attr in STRING_BUILDERS:
                return self.first_taint(arguments)
        return None

    def sink_for(self, node):
        name = self.resolve(node.func)
        last = name.rsplit(".", 1)[-1] if name else None
        spec = SINKS.get(name) or LAST_SEGMENT_SINKS.get(last)
        display = name
        if name in SHELL_CALLS:
            shell_on = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                           for kw in node.keywords)
            if shell_on:
                spec, display = ("AST001", 0, ("args", "cmd")), f"{name}(shell=True)"
        if spec is None and isinstance(node.func, ast.Attribute) and node.func.attr in SQL_METHODS:
            spec, display = ("AST003", 0, ("sql", "query", "statement")), f"{name or node.func.attr}()"
        if name == "yaml.load":
            loaders = [kw.value for kw in node.keywords if kw.arg == "Loader"] + list(node.args[1:2])
            if any("Safe" in (self.resolve(loader) or "") for loader in loaders):
                spec = None
        if spec is None:
            return None
        rule_id, index, keywords = spec
        arguments = list(node.args[index:index + 1]) + [kw.value for kw in node.keywords if kw.arg in keywords]
        return rule_id, display or last, arguments

    def hit(self, node, rule_id, display, taint, via=None):
        if taint.origin.startswith("param:"):
            if not self.report and self.funcs:
                self.funcs[-1].sink_params.setdefault(taint.origin[6:], (rule_id, display))
            return
        if not self.report:
            return
        line = node.lineno
        if (line, rule_id) in self.seen:
            return
        self.seen.add((line, rule_id))
        text = self.code.lines[line - 1] if 0 < line <= len(self.code.lines) else ""
        if SUPPRESSION.search(text):
            return
        rule = RULES_BY_ID[rule_id]
        helper = f" through helper {via}()" if via else ""
        self.findings.append(Finding(
            rule_id=rule.id, title=rule.title, severity=rule.severity, file=self.code.name,
            line=line, snippet=text.strip()[:200],
            message=f"{rule.message} Flow: {taint.origin} (line {taint.line}) -> {display}{helper}.",
            recommendation=rule.recommendation, cwe=rule.cwe,
        ))

    def visit_Call(self, node):
        self.generic_visit(node)
        sink = self.sink_for(node)
        if sink:
            rule_id, display, arguments = sink
            for argument in arguments:
                taint = self.taint(argument)
                if taint:
                    self.hit(node, rule_id, display, taint)
        local = self.local_function(node)
        if local:
            name, summary = local
            for param, argument in self.mapped_args(node, summary):
                if param in summary.sink_params:
                    taint = self.taint(argument)
                    if taint:
                        rule_id, display = summary.sink_params[param]
                        self.hit(node, rule_id, display, taint, via=name)

    def visit_Assign(self, node):
        self.visit(node.value)
        taint = self.taint(node.value)
        for target in node.targets:
            self.bind(target, taint)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self.visit(node.value)
            self.bind(node.target, self.taint(node.value))

    def visit_AugAssign(self, node):
        self.visit(node.value)
        self.bind(node.target, self.taint(node.value) or self.taint(node.target))

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        self.bind(node.target, self.taint(node.value))

    def visit_For(self, node):
        self.visit(node.iter)
        self.bind(node.target, self.taint(node.iter))
        for statement in node.body + node.orelse:
            self.visit(statement)

    visit_AsyncFor = visit_For

    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self.bind(item.optional_vars, self.taint(item.context_expr))
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def visit_comprehension_node(self, node):
        for generator in node.generators:
            self.visit(generator.iter)
            self.bind(generator.target, self.taint(generator.iter))
            for condition in generator.ifs:
                self.visit(condition)
        for part in ([node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]):
            self.visit(part)

    visit_ListComp = visit_SetComp = visit_GeneratorExp = visit_DictComp = visit_comprehension_node

    def is_route(self, node):
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            name = self.resolve(target)
            if name and name.rsplit(".", 1)[-1] in ROUTE_DECORATORS:
                return True
        return False

    def visit_FunctionDef(self, node):
        positional = [a.arg for a in node.args.posonlyargs + node.args.args]
        if positional and positional[0] in ("self", "cls"):
            positional = positional[1:]
        keyword_only = [a.arg for a in node.args.kwonlyargs]
        summary = self.summaries.setdefault(node.name, Summary(params=positional, kwonly=keyword_only))
        summary.params, summary.kwonly = positional, keyword_only

        scope = {}
        route = self.is_route(node)
        for name in positional + keyword_only:
            if not self.report:
                scope[name] = Taint(f"param:{name}", node.lineno)
            elif route:
                scope[name] = Taint(f"route parameter '{name}'", node.lineno)
            else:
                scope[name] = None
        self.scopes.append(scope)
        self.funcs.append(summary)
        for statement in node.body:
            self.visit(statement)
        self.funcs.pop()
        self.scopes.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Return(self, node):
        if node.value is None:
            return
        self.visit(node.value)
        if self.report or not self.funcs:
            return
        taint = self.taint(node.value)
        if taint is None:
            return
        summary = self.funcs[-1]
        if taint.origin.startswith("param:"):
            summary.return_params.add(taint.origin[6:])
        elif summary.returns_source is None:
            summary.returns_source = taint


def check(code: CodeInput) -> list[Finding]:
    if code.language not in ("python", "unknown"):
        return []
    try:
        tree = ast.parse(code.text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    summaries: dict = {}
    for _ in range(3):
        Analyzer(code, tree, summaries, report=False).visit(tree)
    final = Analyzer(code, tree, summaries, report=True)
    final.visit(tree)
    return final.findings
