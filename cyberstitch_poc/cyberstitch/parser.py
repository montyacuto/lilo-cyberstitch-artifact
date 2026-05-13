import re
from pathlib import Path

from .sqir import (
    ConfigModule,
    FlowModule,
    Param,
    PathQuery,
    PathVariable,
    Predicate,
    Query,
    expr,
    stable_source_hash,
)


METADATA_RE = re.compile(r"^\s*\*\s*@([A-Za-z0-9_.-]+)\s+(.*?)\s*$", re.MULTILINE)
IMPORT_RE = re.compile(r"^\s*import\s+(.+?)\s*$", re.MULTILINE)
CONFIG_RE = re.compile(
    r"module\s+(\w+)\s+implements\s+([\w:]+)\s*\{(.*?)^\}",
    re.DOTALL | re.MULTILINE,
)
PREDICATE_RE = re.compile(
    r"predicate\s+(\w+)\s*\((.*?)\)\s*\{(.*?)^\s*\}",
    re.DOTALL | re.MULTILINE,
)
FLOW_RE = re.compile(r"^\s*module\s+(\w+)\s*=\s*(.+?);\s*$", re.MULTILINE)
FROM_RE = re.compile(r"^\s*from\s+(.+?)\s*$", re.MULTILINE)
WHERE_RE = re.compile(r"^\s*where\s+(.+?)\s*$", re.MULTILINE)
SELECT_RE = re.compile(r"^\s*select\s+(.+?)\s*$", re.MULTILINE)

UNSUPPORTED_RE = re.compile(
    r"^\s*(class|private|cached|pragma|bindingset|override|forall|if|then|else)\b",
    re.MULTILINE,
)


def parse_query(path):
    path = Path(path)
    text = path.read_text()
    if UNSUPPORTED_RE.search(text):
        raise ValueError("{} uses unsupported CodeQL constructs".format(path))

    metadata = {key: value for key, value in METADATA_RE.findall(text)}
    imports = [
        item for item in IMPORT_RE.findall(text) if not item.endswith("::PathGraph")
    ]

    config_modules = []
    for name, signature, body in CONFIG_RE.findall(text):
        predicates = []
        for pred_name, params, pred_body in PREDICATE_RE.findall(body):
            body_text = _clean(pred_body)
            predicates.append(
                Predicate(
                    name=pred_name,
                    params=_parse_params(params),
                    role=_role_for_predicate(pred_name),
                    expression=parse_expression(body_text),
                    source_hash=stable_source_hash(body_text),
                )
            )
        config_modules.append(
            ConfigModule(name=name, signature=signature, predicates=predicates)
        )

    flow_modules = [_parse_flow(name, expression) for name, expression in FLOW_RE.findall(text)]
    path_query = _parse_path_query(
        _first(FROM_RE, text), _first(WHERE_RE, text), _first(SELECT_RE, text)
    )
    query = Query(
        source_path=str(path),
        language=_infer_language(imports),
        metadata=metadata,
        imports=imports,
        config_modules=config_modules,
        flow_modules=flow_modules,
        path_query=path_query,
        provenance_hash=stable_source_hash(text),
    )
    query.validate()
    return query


def parse_expression(text):
    text = _clean(text)
    if text.startswith("exists(") and _matching_close(text, len("exists")) == len(text) - 1:
        return _parse_exists(text)

    for kind, separator in (("or", "or"), ("and", "and")):
        parts = _split_top_level_word(text, separator)
        if len(parts) > 1:
            return expr(kind, terms=[parse_expression(part) for part in parts])

    eq_index = _find_top_level_equals(text)
    if eq_index >= 0:
        return expr(
            "eq",
            left=parse_term(text[:eq_index].strip()),
            right=parse_term(text[eq_index + 1 :].strip()),
        )

    return parse_term(text)


def parse_term(text):
    text = _clean(text)
    if not text:
        raise ValueError("empty CodeQL expression")
    if text.startswith('"') and text.endswith('"'):
        return expr("string", value=_unquote(text))
    if re.fullmatch(r"\d+", text):
        return expr("int", value=int(text))

    segments = _split_top_level_char(text, ".")
    node = _parse_base_segment(segments[0])
    for segment in segments[1:]:
        method, args = _parse_call_segment(segment)
        if method == "getArgument" and len(args) == 1 and args[0]["kind"] == "int":
            node = expr("argument_selection", receiver=node, index=args[0]["value"])
        elif method == "hasQualifiedName":
            node = expr(
                "qualified_name_check",
                receiver=node,
                name_parts=[arg["value"] for arg in args if arg["kind"] == "string"],
            )
        else:
            node = expr("method_call", receiver=node, method=method, args=args)
    return node


def format_query(query):
    query.validate()
    lines = ["/**"]
    for key, value in query.metadata.items():
        lines.append(" * @{} {}".format(key, value))
    lines.append(" */")
    lines.append("")
    for item in query.imports:
        lines.append("import {}".format(item))
    lines.append("")
    for module in query.config_modules:
        lines.append("module {} implements {} {{".format(module.name, module.signature))
        for predicate in module.predicates:
            params = ", ".join(
                "{} {}".format(param.type, param.name) for param in predicate.params
            )
            lines.append("  predicate {}({}) {{".format(predicate.name, params))
            body = format_expression(predicate.expression)
            for body_line in _indent_expr(body).splitlines():
                lines.append("    {}".format(body_line.rstrip()))
            lines.append("  }")
            lines.append("")
        lines.append("}")
        lines.append("")
    for module in query.flow_modules:
        lines.append("module {} = {};".format(module.name, module.expression))
        lines.append("import {}::PathGraph".format(module.name))
    lines.append("")
    lines.append("from {}".format(_format_path_from(query.path_query)))
    lines.append("where {}::flowPath({}, {})".format(
        query.path_query.flow_module,
        query.path_query.source_var,
        query.path_query.sink_var,
    ))
    lines.append("select {}".format(_format_select(query.path_query)))
    lines.append("")
    return "\n".join(lines)


def format_expression(node):
    kind = node["kind"]
    if kind == "exists":
        vars_text = ", ".join(
            "{} {}".format(var["type"], var["name"]) for var in node["vars"]
        )
        return "exists({} | {})".format(vars_text, format_expression(node["body"]))
    if kind in {"and", "or"}:
        sep = " {} ".format(kind)
        return sep.join(format_expression(term) for term in node["terms"])
    if kind == "eq":
        return "{} = {}".format(format_expression(node["left"]), format_expression(node["right"]))
    if kind == "var":
        return node["name"]
    if kind == "string":
        return '"{}"'.format(str(node["value"]).replace("\\", "\\\\").replace('"', '\\"'))
    if kind == "int":
        return str(node["value"])
    if kind == "type_ref":
        return node["name"]
    if kind == "qualified_call":
        return "{}::{}({})".format(
            node["namespace"],
            node["name"],
            ", ".join(format_expression(arg) for arg in node.get("args", [])),
        )
    if kind == "method_call":
        return "{}.{}({})".format(
            format_expression(node["receiver"]),
            node["method"],
            ", ".join(format_expression(arg) for arg in node.get("args", [])),
        )
    if kind == "argument_selection":
        return "{}.getArgument({})".format(
            format_expression(node["receiver"]), node["index"]
        )
    if kind == "qualified_name_check":
        parts = ", ".join(format_expression(expr("string", value=part)) for part in node["name_parts"])
        return "{}.hasQualifiedName({})".format(format_expression(node["receiver"]), parts)
    if kind == "predicate_call":
        return "{}({})".format(
            node["name"],
            ", ".join(format_expression(arg) for arg in node.get("args", [])),
        )
    if kind == "path_select":
        return _format_path_select(node)
    raise ValueError("unsupported SQIR expression kind {}".format(kind))


def _parse_params(text):
    params = []
    for item in [part.strip() for part in text.split(",") if part.strip()]:
        pieces = item.rsplit(" ", 1)
        if len(pieces) != 2:
            raise ValueError("Unsupported parameter form: {}".format(item))
        params.append(Param(type=pieces[0].strip(), name=pieces[1].strip()))
    return params


def _parse_flow(name, expression):
    match = re.fullmatch(r"(\w+)::(\w+)<(\w+)>", expression.strip())
    if not match:
        raise ValueError("Unsupported flow module expression: {}".format(expression))
    framework, kind, config = match.groups()
    return FlowModule(name=name, framework=framework, kind=kind, config=config)


def _parse_path_query(from_clause, where_clause, select_clause):
    variables = []
    for item in _split_top_level_char(from_clause, ","):
        pieces = item.strip().rsplit(" ", 1)
        if len(pieces) != 2:
            raise ValueError("Unsupported from clause variable: {}".format(item))
        variables.append(PathVariable(type=pieces[0].strip(), name=pieces[1].strip()))

    match = re.fullmatch(r"(\w+)::flowPath\((\w+),\s*(\w+)\)", where_clause.strip())
    if not match:
        raise ValueError("Unsupported path-query where clause: {}".format(where_clause))
    flow_module, source_var, sink_var = match.groups()

    select_parts = _split_top_level_char(select_clause, ",")
    if len(select_parts) != 4:
        raise ValueError("Unsupported path-query select clause: {}".format(select_clause))
    select = expr(
        "path_select",
        node=parse_term(select_parts[0].strip()),
        source=parse_term(select_parts[1].strip()),
        sink=parse_term(select_parts[2].strip()),
        message=_unquote(select_parts[3].strip()),
    )
    return PathQuery(
        variables=variables,
        flow_module=flow_module,
        source_var=source_var,
        sink_var=sink_var,
        select=select,
        message=select["message"],
    )


def _parse_exists(text):
    inner = text[len("exists(") : -1].strip()
    var_text, body_text = _split_top_level_bar(inner)
    variables = []
    for item in _split_top_level_char(var_text, ","):
        pieces = item.strip().rsplit(" ", 1)
        if len(pieces) != 2:
            raise ValueError("Unsupported exists variable declaration: {}".format(item))
        variables.append({"type": pieces[0].strip(), "name": pieces[1].strip()})
    return expr("exists", vars=variables, body=parse_expression(body_text))


def _parse_base_segment(segment):
    segment = segment.strip()
    if re.fullmatch(r"[A-Za-z_]\w*", segment):
        return expr("var", name=segment)
    if "::" in segment:
        namespace, call = segment.split("::", 1)
        name, args = _parse_call_segment(call)
        return expr("qualified_call", namespace=namespace, name=name, args=args)
    if re.fullmatch(r"[A-Za-z_]\w*\(.*\)", segment):
        name, args = _parse_call_segment(segment)
        return expr("predicate_call", name=name, args=args)
    raise ValueError("Unsupported CodeQL term: {}".format(segment))


def _parse_call_segment(segment):
    segment = segment.strip()
    match = re.fullmatch(r"([A-Za-z_]\w*)\((.*)\)", segment, re.DOTALL)
    if not match:
        raise ValueError("Unsupported method call segment: {}".format(segment))
    name, args_text = match.groups()
    args = []
    if args_text.strip():
        args = [parse_term(part.strip()) for part in _split_top_level_char(args_text, ",")]
    return name, args


def _first(regex, text):
    match = regex.search(text)
    return match.group(1).strip() if match else ""


def _clean(text):
    return " ".join(line.strip() for line in str(text).strip().splitlines() if line.strip())


def _role_for_predicate(name):
    return {
        "isSource": "Source",
        "isSink": "Sink",
        "isBarrier": "Barrier",
        "isSanitizer": "Barrier",
    }.get(name, "Helper")


def _infer_language(imports):
    if "java" in imports:
        return "java"
    if "javascript" in imports:
        return "javascript"
    return "unknown"


def _split_top_level_word(text, word):
    parts = []
    start = 0
    depth = 0
    quote = None
    i = 0
    while i < len(text):
        char = text[i]
        if quote:
            if char == "\\":
                i += 2
                continue
            if char == quote:
                quote = None
        elif char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and text.startswith(word, i):
            before = text[i - 1] if i else " "
            after = text[i + len(word)] if i + len(word) < len(text) else " "
            if not (before.isalnum() or before == "_") and not (after.isalnum() or after == "_"):
                parts.append(text[start:i].strip())
                start = i + len(word)
                i = start
                continue
        i += 1
    parts.append(text[start:].strip())
    return [part for part in parts if part]


def _split_top_level_char(text, separator):
    parts = []
    start = 0
    depth = 0
    quote = None
    for i, char in enumerate(text):
        if quote:
            if char == "\\":
                continue
            if char == quote:
                quote = None
        elif char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and char == separator:
            parts.append(text[start:i].strip())
            start = i + 1
    parts.append(text[start:].strip())
    return [part for part in parts if part]


def _split_top_level_bar(text):
    depth = 0
    quote = None
    for i, char in enumerate(text):
        if quote:
            if char == "\\":
                continue
            if char == quote:
                quote = None
        elif char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and char == "|":
            return text[:i].strip(), text[i + 1 :].strip()
    raise ValueError("Unsupported exists block without top-level |: {}".format(text))


def _find_top_level_equals(text):
    depth = 0
    quote = None
    for i, char in enumerate(text):
        if quote:
            if char == "\\":
                continue
            if char == quote:
                quote = None
        elif char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and char == "=":
            before = text[i - 1] if i else ""
            after = text[i + 1] if i + 1 < len(text) else ""
            if before not in {"!", "<", ">", "="} and after != "=":
                return i
    return -1


def _matching_close(text, open_index):
    depth = 0
    quote = None
    for i in range(open_index, len(text)):
        char = text[i]
        if quote:
            if char == "\\":
                continue
            if char == quote:
                quote = None
        elif char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _indent_expr(text):
    return text.replace(" and ", " and\n").replace(" or ", " or\n")


def _format_path_from(path_query):
    return ", ".join("{} {}".format(var.type, var.name) for var in path_query.variables)


def _format_select(path_query):
    return _format_path_select(path_query.select)


def _format_path_select(node):
    return "{}, {}, {}, {}".format(
        format_expression(node["node"]),
        format_expression(node["source"]),
        format_expression(node["sink"]),
        format_expression(expr("string", value=node["message"])),
    )


def _unquote(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return bytes(text[1:-1], "utf-8").decode("unicode_escape")
    return text
