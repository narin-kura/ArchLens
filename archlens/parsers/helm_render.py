"""A small, pure-Python renderer for Helm chart templates.

ArchLens never runs the `helm` binary on an uploaded chart. Instead it renders
the templates itself with the chart's default values.yaml, close enough to
`helm template` for a security review: the Kubernetes objects come out with
their real securityContext, images, resources and service types, so the same
checks run on a chart as on plain manifests.

Supported: {{ }} actions with trim markers, comments, pipelines, parentheses,
variables ($x := ...), if / else if / else, with, range (lists and maps, with
$i, $v := ...), define / include / template, and the Sprig functions charts
lean on most (default, quote, toYaml, nindent, printf, trunc, trimSuffix, ...).
Anything else evaluates to nothing instead of failing, so an exotic template
degrades to missing fields rather than a crash.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

import yaml

_MAX_OUTPUT = 2_000_000   # characters per rendered file
_MAX_DEPTH = 50           # nested include / tpl calls


class RenderError(Exception):
    pass


# ------------------------------------------------------------------ lexing

_ACTION = re.compile(r"\{\{(-\s)?(.*?)(\s-)?\}\}", re.S)


def _split(template: str) -> list[tuple[str, str]]:
    """Split a template into ("text", s) and ("action", s) parts, applying
    the {{- and -}} whitespace trims."""
    parts: list[tuple[str, str]] = []
    pos = 0
    trim_next = False
    for m in _ACTION.finditer(template):
        text = template[pos:m.start()]
        if trim_next:
            text = text.lstrip()
        if m.group(1):
            text = text.rstrip()
        parts.append(("text", text))
        parts.append(("action", m.group(2).strip()))
        trim_next = bool(m.group(3))
        pos = m.end()
    tail = template[pos:]
    parts.append(("text", tail.lstrip() if trim_next else tail))
    return parts


_TOKEN = re.compile(r"""
    (?P<str>"(?:\\.|[^"\\])*")
  | (?P<raw>`[^`]*`)
  | (?P<num>-?\d+(?:\.\d+)?)
  | (?P<assign>:=|=)
  | (?P<op>[()|,])
  | (?P<var>\$[A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*)
  | (?P<field>(?:\.[A-Za-z0-9_]+)+|\.)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
  | (?P<ws>\s+)
""", re.X)


def _tokenize(src: str) -> list[tuple[str, str]]:
    tokens, pos = [], 0
    while pos < len(src):
        m = _TOKEN.match(src, pos)
        if not m:
            raise RenderError(f"cannot read template expression: {src!r}")
        kind = m.lastgroup
        if kind != "ws":
            tokens.append((kind, m.group()))
        pos = m.end()
    return tokens


# ------------------------------------------------------------------ parsing

class _Node:
    pass


class _Text(_Node):
    def __init__(self, text: str):
        self.text = text


class _Output(_Node):
    def __init__(self, expr: str):
        self.expr = expr


class _Block(_Node):
    def __init__(self, kind: str, expr: str):
        self.kind = kind            # if / with / range / define
        self.expr = expr
        self.body: list[_Node] = []
        self.else_body: list[_Node] = []


def _parse(template: str) -> tuple[list[_Node], dict[str, list[_Node]]]:
    root: list[_Node] = []
    defines: dict[str, list[_Node]] = {}
    stack: list[tuple[_Block, list[_Node]]] = []
    current = root

    for kind, value in _split(template):
        if kind == "text":
            if value:
                current.append(_Text(value))
            continue
        if value.startswith("/*") or not value:
            continue
        word, _, rest = value.partition(" ")
        rest = rest.strip()
        if word in ("if", "with", "range", "define", "block"):
            block = _Block("define" if word == "block" else word, rest)
            current.append(block)
            stack.append((block, current))
            current = block.body
        elif word == "else":
            if not stack:
                raise RenderError("else without if")
            block, _ = stack[-1]
            sub, _, sub_rest = rest.partition(" ")
            if sub in ("if", "with"):
                # `else if x` is an if nested in the else branch that
                # shares the outer block's single `end`.
                nested = _Block(sub, sub_rest.strip())
                block.else_body.append(nested)
                stack[-1] = (nested, stack[-1][1])
                nested._chained_parent = block  # type: ignore[attr-defined]
                current = nested.body
            else:
                current = block.else_body
        elif word == "end":
            if not stack:
                raise RenderError("end without block")
            block, parent = stack.pop()
            current = parent
            if block.kind == "define":
                name = _literal_string(block.expr.split()[0]) if block.expr else ""
                defines[name] = block.body
                parent.remove(block)
                if word == "end" and block.expr and len(block.expr.split()) > 1:
                    # {{ block "name" . }} also renders in place.
                    parent.append(_Output(f'include {block.expr}'))
        else:
            current.append(_Output(value))
    if stack:
        raise RenderError("unclosed block")
    return root, defines


def _literal_string(token: str) -> str:
    if token.startswith('"'):
        return json.loads(token)
    if token.startswith("`"):
        return token[1:-1]
    return token


# --------------------------------------------------------------- evaluation

def _truthy(v: Any) -> bool:
    if v is None or v is False:
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v != 0
    if isinstance(v, (str, list, dict, tuple)):
        return len(v) > 0
    return True


def _to_text(v: Any) -> str:
    if v is None:
        return ""
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    if isinstance(v, (dict, list)):
        # Go prints maps as map[...]; charts almost always pipe these through
        # toYaml, so emit YAML flow style rather than Python repr.
        return yaml.safe_dump(v, default_flow_style=True).strip()
    return str(v)


def _to_yaml(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, (dict, list)) and not v:
        return "{}" if isinstance(v, dict) else "[]"
    return yaml.safe_dump(v, default_flow_style=False, sort_keys=False).rstrip("\n")


def _indent(n: Any, s: Any) -> str:
    pad = " " * int(n)
    return "\n".join(pad + line if line else line for line in _to_text(s).split("\n"))


def _printf(fmt: str, *args: Any) -> str:
    out, i = [], 0
    pieces = re.split(r"(%[-+ #0]*\d*(?:\.\d+)?[sdvqfx%])", fmt)
    for piece in pieces:
        if piece.startswith("%") and len(piece) > 1:
            verb = piece[-1]
            if verb == "%":
                out.append("%")
                continue
            arg = args[i] if i < len(args) else None
            i += 1
            if verb == "q":
                out.append(json.dumps(_to_text(arg)))
            elif verb in "df" and isinstance(arg, (int, float)):
                out.append(("%" + piece[1:]) % arg)
            else:
                out.append(_to_text(arg))
        else:
            out.append(piece)
    return "".join(out)


def _semver_compare(*_: Any) -> bool:
    # Charts gate apiVersions on the cluster version; assume a current cluster.
    return True


class _Renderer:
    def __init__(self, root_ctx: dict, defines: dict[str, list[_Node]]):
        self.root = root_ctx
        self.defines = defines
        self.depth = 0
        self.funcs = {
            "default": lambda d, v=None: v if _truthy(v) else d,
            "quote": lambda *a: " ".join(json.dumps(_to_text(x)) for x in a),
            "squote": lambda *a: " ".join("'" + _to_text(x) + "'" for x in a),
            "toYaml": _to_yaml,
            "toJson": lambda v: json.dumps(v),
            "toString": _to_text,
            "nindent": lambda n, s: "\n" + _indent(n, s),
            "indent": _indent,
            "trunc": lambda n, s: _to_text(s)[:int(n)] if int(n) >= 0 else _to_text(s)[int(n):],
            "trimSuffix": lambda suf, s: _to_text(s)[:-len(suf)] if suf and _to_text(s).endswith(suf) else _to_text(s),
            "trimPrefix": lambda pre, s: _to_text(s)[len(pre):] if pre and _to_text(s).startswith(pre) else _to_text(s),
            "trim": lambda s: _to_text(s).strip(),
            "upper": lambda s: _to_text(s).upper(),
            "lower": lambda s: _to_text(s).lower(),
            "title": lambda s: _to_text(s).title(),
            "replace": lambda old, new, s: _to_text(s).replace(old, new),
            "contains": lambda sub, s: _to_text(sub) in _to_text(s),
            "hasPrefix": lambda pre, s: _to_text(s).startswith(_to_text(pre)),
            "hasSuffix": lambda suf, s: _to_text(s).endswith(_to_text(suf)),
            "printf": _printf,
            "print": lambda *a: "".join(_to_text(x) for x in a),
            "println": lambda *a: " ".join(_to_text(x) for x in a) + "\n",
            "b64enc": lambda s: base64.b64encode(_to_text(s).encode()).decode(),
            "b64dec": lambda s: base64.b64decode(_to_text(s).encode()).decode(errors="replace"),
            "sha256sum": lambda s: hashlib.sha256(_to_text(s).encode()).hexdigest(),
            "int": lambda v: int(float(v)) if _truthy(v) else 0,
            "int64": lambda v: int(float(v)) if _truthy(v) else 0,
            "float64": lambda v: float(v) if _truthy(v) else 0.0,
            "not": lambda v: not _truthy(v),
            "and": lambda *a: next((x for x in a if not _truthy(x)), a[-1] if a else None),
            "or": lambda *a: next((x for x in a if _truthy(x)), a[-1] if a else None),
            "eq": lambda a, *b: any(a == x for x in b),
            "ne": lambda a, b: a != b,
            "lt": lambda a, b: a < b,
            "le": lambda a, b: a <= b,
            "gt": lambda a, b: a > b,
            "ge": lambda a, b: a >= b,
            "empty": lambda v: not _truthy(v),
            "required": lambda _msg, v=None: v,
            "fail": lambda msg: (_ for _ in ()).throw(RenderError(f"chart called fail: {msg}")),
            "ternary": lambda a, b, cond: a if _truthy(cond) else b,
            "hasKey": lambda d, k: isinstance(d, dict) and k in d,
            "get": lambda d, k: d.get(k) if isinstance(d, dict) else None,
            "dict": lambda *a: {str(a[i]): a[i + 1] for i in range(0, len(a) - 1, 2)},
            "list": lambda *a: list(a),
            "merge": lambda dst, *srcs: {**{k: v for s in reversed(srcs) for k, v in (s or {}).items()}, **(dst or {})},
            "keys": lambda *ds: [k for d in ds for k in (d or {})],
            "values": lambda d: list((d or {}).values()),
            "first": lambda v: v[0] if v else None,
            "last": lambda v: v[-1] if v else None,
            "join": lambda sep, v: _to_text(sep).join(_to_text(x) for x in (v or [])),
            "splitList": lambda sep, s: _to_text(s).split(sep),
            "kindIs": lambda kind, v: _kind(v) == kind,
            "typeIs": lambda kind, v: _kind(v) == kind,
            "kindOf": lambda v: _kind(v),
            "semverCompare": _semver_compare,
            "lookup": lambda *a: {},
            "randAlphaNum": lambda n: "x" * int(n),
            "uuidv4": lambda: "00000000-0000-0000-0000-000000000000",
            "now": lambda: "",
            "date": lambda *a: "",
            "toDate": lambda *a: "",
            "regexMatch": lambda pat, s: re.search(pat, _to_text(s)) is not None,
            "regexReplaceAll": lambda pat, s, rep: re.sub(pat, rep.replace("${1}", r"\1"), _to_text(s)),
            "len": lambda v: len(v) if v is not None else 0,
            "index": lambda v, *keys: _index(v, keys),
            "fromYaml": lambda s: yaml.safe_load(_to_text(s)) or {},
            "deepCopy": lambda v: json.loads(json.dumps(v)),
            "mustMerge": lambda dst, *srcs: {**{k: v for s in reversed(srcs) for k, v in (s or {}).items()}, **(dst or {})},
        }

    # -- nodes

    def render(self, nodes: list[_Node], dot: Any, variables: dict) -> str:
        out: list[str] = []
        for node in nodes:
            if isinstance(node, _Text):
                out.append(node.text)
            elif isinstance(node, _Output):
                value = self.eval_action(node.expr, dot, variables)
                if value is not _ASSIGNED:
                    out.append(_to_text(value))
            elif isinstance(node, _Block):
                out.append(self.render_block(node, dot, variables))
            if sum(len(s) for s in out) > _MAX_OUTPUT:
                raise RenderError("rendered output too large")
        return "".join(out)

    def render_block(self, block: _Block, dot: Any, variables: dict) -> str:
        if block.kind == "if":
            cond = self.eval_action(block.expr, dot, variables)
            branch = block.body if _truthy(cond) else block.else_body
            return self.render(branch, dot, variables)
        if block.kind == "with":
            value = self.eval_action(block.expr, dot, variables)
            if _truthy(value):
                return self.render(block.body, value, variables)
            return self.render(block.else_body, dot, variables)
        if block.kind == "range":
            names, expr = _range_vars(block.expr)
            items = self.eval_action(expr, dot, variables)
            if not _truthy(items):
                return self.render(block.else_body, dot, variables)
            pairs = sorted(items.items()) if isinstance(items, dict) else list(enumerate(items)) \
                if isinstance(items, list) else list(enumerate(range(int(items)))) if isinstance(items, int) else []
            out = []
            for key, value in pairs:
                scope = dict(variables)
                if len(names) == 2:
                    scope[names[0]], scope[names[1]] = key, value
                elif len(names) == 1:
                    scope[names[0]] = value
                out.append(self.render(block.body, value, scope))
            return "".join(out)
        return ""

    # -- expressions

    def eval_action(self, expr: str, dot: Any, variables: dict) -> Any:
        tokens = _tokenize(expr)
        if len(tokens) >= 2 and tokens[0][0] == "var" and tokens[1][0] == "assign":
            variables[tokens[0][1]] = self.eval_pipeline(tokens[2:], dot, variables)
            return _ASSIGNED
        return self.eval_pipeline(tokens, dot, variables)

    def eval_pipeline(self, tokens: list[tuple[str, str]], dot: Any, variables: dict) -> Any:
        commands: list[list[tuple[str, str]]] = [[]]
        depth = 0
        for tok in tokens:
            if tok == ("op", "(" ):
                depth += 1
            elif tok == ("op", ")"):
                depth -= 1
            if tok == ("op", "|") and depth == 0:
                commands.append([])
            else:
                commands[-1].append(tok)
        value: Any = _NO_VALUE
        for command in commands:
            value = self.eval_command(command, dot, variables, value)
        return None if value is _NO_VALUE else value

    def eval_command(self, tokens, dot, variables, piped) -> Any:
        operands = self._operands(tokens, dot, variables)
        if not operands:
            return piped
        head_kind, head = operands[0]
        if head_kind == "field" and head.endswith(".APIVersions.Has"):
            # .Capabilities.APIVersions.Has "x/v1" — assume a current cluster.
            return True
        if head_kind == "ident":
            args = [self._operand_value(op, dot, variables) for op in operands[1:]]
            if piped is not _NO_VALUE:
                args.append(piped)
            return self.call(head, args, dot, variables)
        return self._operand_value(operands[0], dot, variables)

    def _operands(self, tokens, dot, variables):
        """Group tokens into operands, folding (...) into one sub-pipeline."""
        out, i = [], 0
        while i < len(tokens):
            kind, text = tokens[i]
            if (kind, text) == ("op", "("):
                depth, j = 1, i + 1
                while j < len(tokens) and depth:
                    if tokens[j] == ("op", "("):
                        depth += 1
                    elif tokens[j] == ("op", ")"):
                        depth -= 1
                    j += 1
                inner = tokens[i + 1:j - 1]
                out.append(("value", self.eval_pipeline(inner, dot, variables)))
                # (expr).Field chains straight after the parenthesis.
                if j < len(tokens) and tokens[j][0] == "field" and tokens[j][1] != ".":
                    out[-1] = ("value", _walk(out[-1][1], tokens[j][1]))
                    j += 1
                i = j
                continue
            if kind == "op":
                i += 1
                continue
            out.append((kind, text))
            i += 1
        return out

    def _operand_value(self, operand, dot, variables) -> Any:
        kind, text = operand
        if kind == "value":
            return text
        if kind == "str":
            return json.loads(text)
        if kind == "raw":
            return text[1:-1]
        if kind == "num":
            return float(text) if "." in text else int(text)
        if kind == "field":
            return dot if text == "." else _walk(dot, text)
        if kind == "var":
            name, _, path = text.partition(".")
            base = self.root if name == "$" else variables.get(name)
            return _walk(base, "." + path) if path else base
        if kind == "ident":
            if text in ("true", "false"):
                return text == "true"
            if text == "nil":
                return None
            return self.call(text, [], dot, variables)
        return None

    def call(self, name: str, args: list, dot: Any, variables: dict) -> Any:
        if name in ("include", "template"):
            if not args:
                return ""
            body = self.defines.get(_to_text(args[0]))
            if body is None:
                return ""
            self.depth += 1
            if self.depth > _MAX_DEPTH:
                raise RenderError("include nested too deeply")
            try:
                return self.render(body, args[1] if len(args) > 1 else None, {})
            finally:
                self.depth -= 1
        if name == "tpl":
            if not args:
                return ""
            self.depth += 1
            if self.depth > _MAX_DEPTH:
                raise RenderError("tpl nested too deeply")
            try:
                nodes, defines = _parse(_to_text(args[0]))
                self.defines.update(defines)
                return self.render(nodes, args[1] if len(args) > 1 else dot, {})
            finally:
                self.depth -= 1
        func = self.funcs.get(name)
        if func is None:
            return None
        try:
            return func(*args)
        except RenderError:
            raise
        except Exception:
            return None


_ASSIGNED = object()
_NO_VALUE = object()


def _walk(base: Any, path: str) -> Any:
    value = base
    for part in path.strip(".").split("."):
        if not part:
            continue
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return value


def _index(value: Any, keys) -> Any:
    for k in keys:
        if isinstance(value, dict):
            value = value.get(k)
        elif isinstance(value, list) and isinstance(k, int) and 0 <= k < len(value):
            value = value[k]
        else:
            return None
    return value


def _kind(v: Any) -> str:
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float64"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "slice"
    if isinstance(v, dict):
        return "map"
    return "invalid"


def _range_vars(expr: str) -> tuple[list[str], str]:
    m = re.match(r"^\s*(\$\w*)\s*(?:,\s*(\$\w*)\s*)?:=\s*(.*)$", expr, re.S)
    if not m:
        return [], expr
    names = [n for n in (m.group(1), m.group(2)) if n]
    return names, m.group(3)


# --------------------------------------------------------------- public API

def build_context(values: dict, chart_meta: dict, release_name: str, namespace: str = "default") -> dict:
    return {
        "Values": values or {},
        "Release": {"Name": release_name, "Namespace": namespace, "Service": "Helm",
                    "IsInstall": True, "IsUpgrade": False, "Revision": 1},
        "Chart": {"Name": chart_meta.get("name", release_name), "Version": chart_meta.get("version", ""),
                  "AppVersion": chart_meta.get("appVersion", ""),
                  "Description": chart_meta.get("description", "")},
        "Capabilities": {"KubeVersion": {"Version": "v1.30.0", "GitVersion": "v1.30.0",
                                         "Major": "1", "Minor": "30"},
                         "APIVersions": {}},
        "Template": {"Name": "", "BasePath": "templates"},
        "Files": {},
    }


def collect_defines(sources: list[str]) -> dict[str, list[_Node]]:
    defines: dict[str, list[_Node]] = {}
    for src in sources:
        try:
            _, found = _parse(src)
        except RenderError:
            continue
        defines.update(found)
    return defines


def render_template(template: str, context: dict, defines: dict[str, list[_Node]]) -> str:
    nodes, own_defines = _parse(template)
    renderer = _Renderer(context, {**defines, **own_defines})
    return renderer.render(nodes, context, {})
