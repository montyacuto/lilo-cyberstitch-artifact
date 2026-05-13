import hashlib
import json
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
    query_from_dict,
)
from .semantic import semantic_concepts_for_query


FCIR_VERSION = "fcir-v2"
STITCH_PROGRAMS_FILENAME = "programs.json"
PROVENANCE_FILENAME = "provenance.json"


def _symbol(value, prefix="sym"):
    text = str(value)
    text = re.sub(r"[^A-Za-z0-9_]+", "_", text).strip("_")
    text = re.sub(r"_+", "_", text)
    if not text:
        text = prefix
    if text[0].isdigit():
        text = "{}_{}".format(prefix, text)
    return text


def _hash_token(value, prefix="H"):
    return "{}_{}".format(prefix, hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:16])


def _atom(value):
    if isinstance(value, int):
        return str(value)
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return '"{}"'.format(escaped)


def query_to_fcir(query):
    """Return the STITCH-readable FCIR term for a SQIR query.

    Metadata and original strings are intentionally omitted from the term and
    written to provenance instead. STITCH sees typed semantic atoms; CyberSTITCH
    keeps the mapping needed to reconstruct SQIR/CodeQL.
    """
    program, _ = query_to_fcir_entry(query, "query")
    return program


def query_to_fcir_entry(query, program_id):
    query.validate()
    cwe = _cwe_for_query(query)
    rule_id = query.metadata.get("id", "")
    semantic_nodes = []

    imports = " ".join("(Import {})".format(_symbol(item, "import")) for item in query.imports)
    modules = " ".join(
        _module_to_stitch(module, program_id, semantic_nodes)
        for module in query.config_modules
    )
    flows = " ".join(_flow_to_stitch(module, program_id, semantic_nodes) for module in query.flow_modules)
    path_query = _path_query_to_stitch(query.path_query, program_id, semantic_nodes)
    concept_nodes = semantic_concepts_for_query(query, program_id)
    semantic_nodes.extend(concept_nodes)
    concepts = " ".join(node["term"] for node in concept_nodes)
    program = (
        "(Query (FCIRVersion {}) (ProgramId {}) (SQIRHash {}) (Language {}) "
        "(RuleId {}){} (Imports {}) (Modules {}) (Flows {}) {} (Concepts {}))"
    ).format(
        _symbol(FCIR_VERSION, "version"),
        _symbol(program_id, "program"),
        _hash_token(query.stable_hash(), "SQIR"),
        _symbol(query.language, "lang"),
        _symbol(rule_id, "rule"),
        " (CWE CWE_{:03d})".format(cwe) if cwe else "",
        imports,
        modules,
        flows,
        path_query,
        concepts,
    )
    semantic_nodes.insert(
        0,
        {
            "id": "{}:query".format(program_id),
            "kind": "Query",
            "role": "PathProblem",
            "name": rule_id,
            "target": "CWE-{}".format(cwe) if cwe else "",
            "term": program,
            "source_hash": query.stable_hash(),
            "source": {"path": query.source_path, "span": None},
        },
    )
    provenance = {
        "program_id": program_id,
        "name": query.source_path,
        "language": query.language,
        "sqir_hash": query.stable_hash(),
        "provenance_hash": query.provenance_hash,
        "cwe": cwe,
        "rule_id": rule_id,
        "program": program,
        "sqir": query.to_dict(),
        "semantic_nodes": semantic_nodes,
        "term_index": [
            {
                "term": node["term"],
                "semantic_node_id": node["id"],
                "kind": node["kind"],
                "role": node.get("role", ""),
                "target": node.get("target", ""),
            }
            for node in semantic_nodes
        ],
    }
    return program, provenance


def _legacy_query_to_fcir(query):
    query.validate()
    metadata = " ".join(
        "(Meta {} {})".format(_atom(key), _atom(value))
        for key, value in sorted(query.metadata.items())
    )
    imports = " ".join("(Import {})".format(_atom(item)) for item in query.imports)
    modules = " ".join(_module_to_fcir(module) for module in query.config_modules)
    flows = " ".join(_flow_to_fcir(module) for module in query.flow_modules)
    cwe = _cwe_for_query(query)
    cwe_text = " (CWE {})".format(cwe) if cwe else ""
    return (
        "(Query (FCIRVersion {}) (SQIRVersion {}) (Hash {}){} "
        "(SourcePath {}) (Language {}) (Metadata {}) (Imports {}) "
        "(Modules {}) (Flows {}) {})"
    ).format(
        _atom(FCIR_VERSION),
        _atom(query.version),
        _atom(query.stable_hash()),
        cwe_text,
        _atom(query.source_path),
        _atom(query.language),
        metadata,
        imports,
        modules,
        flows,
        _path_query_to_fcir(query.path_query),
    )


def fcir_to_query(program, provenance_entry=None):
    if provenance_entry and provenance_entry.get("sqir"):
        query = query_from_dict(provenance_entry["sqir"])
        query.validate()
        return query

    node = parse_sexpr(program)
    if not node or node[0] != "Query":
        raise ValueError("FCIR program does not start with Query")
    sections = _sections(node[1:])
    if "SourcePath" not in sections:
        raise ValueError("STITCH-compatible FCIR requires provenance for SQIR inversion")
    metadata = {
        item[1]: item[2]
        for item in sections["Metadata"][1:]
        if item and item[0] == "Meta"
    }
    imports = [
        item[1] for item in sections["Imports"][1:] if item and item[0] == "Import"
    ]
    modules = []
    for module_node in sections["Modules"][1:]:
        if not module_node or module_node[0] != "ConfigModule":
            continue
        modules.append(_module_from_fcir(module_node))
    flows = []
    for flow_node in sections["Flows"][1:]:
        if not flow_node or flow_node[0] != "Flow":
            continue
        flows.append(
            FlowModule(
                name=flow_node[4],
                framework=flow_node[1],
                kind=flow_node[2],
                config=flow_node[3],
            )
        )
    query = Query(
        source_path=sections["SourcePath"][1],
        language=sections["Language"][1],
        metadata=metadata,
        imports=imports,
        config_modules=modules,
        flow_modules=flows,
        path_query=_path_query_from_fcir(sections["PathQuery"]),
    )
    query.validate()
    return query


def write_corpus(sqir_json_paths, output_path):
    output_path = Path(output_path)
    output_dir = output_path if output_path.suffix == "" else output_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    programs_path = output_dir / STITCH_PROGRAMS_FILENAME
    provenance_path = output_dir / PROVENANCE_FILENAME

    programs = []
    provenance = []
    for path in sqir_json_paths:
        with open(path) as handle:
            query = query_from_dict(json.load(handle))
        program_id = "q{}".format(len(programs))
        program, entry = query_to_fcir_entry(query, program_id)
        inverted = fcir_to_query(program, provenance_entry=entry)
        if inverted.stable_hash() != query.stable_hash():
            raise ValueError("{} did not survive FCIR inversion".format(path))
        programs.append(program)
        provenance.append(entry)

    with open(programs_path, "w") as handle:
        json.dump(programs, handle, indent=2)
    with open(provenance_path, "w") as handle:
        json.dump(
            {
                "format": "cyberstitch-fcir-provenance",
                "version": FCIR_VERSION,
                "programs_file": programs_path.name,
                "programs": provenance,
            },
            handle,
            indent=2,
        )
    with open(output_path, "w") as handle:
        json.dump(
            {
                "format": "cyberstitch-fcir-index",
                "version": FCIR_VERSION,
                "stitch_format": "programs-list",
                "programs_file": str(programs_path),
                "provenance_file": str(provenance_path),
                "programs": [
                    {
                        "program_id": item["program_id"],
                        "name": item["name"],
                        "language": item["language"],
                        "sqir_hash": item["sqir_hash"],
                        "cwe": item["cwe"],
                        "rule_id": item["rule_id"],
                    }
                    for item in provenance
                ],
            },
            handle,
            indent=2,
        )
    return {
        "programs": programs,
        "provenance": provenance,
        "programs_path": str(programs_path),
        "provenance_path": str(provenance_path),
        "index_path": str(output_path),
    }


def _module_to_stitch(module, program_id, semantic_nodes):
    predicates = " ".join(
        _predicate_to_stitch(module, predicate, program_id, semantic_nodes)
        for predicate in module.predicates
    )
    term = "(ConfigModule {} {} (Predicates {}))".format(
        _symbol(module.name, "config"), _symbol(module.signature, "sig"), predicates
    )
    semantic_nodes.append(
        {
            "id": "{}:config:{}".format(program_id, module.name),
            "kind": "ConfigModule",
            "role": "FlowConfig",
            "name": module.name,
            "target": module.signature,
            "term": term,
            "source_hash": "",
            "source": {"path": "", "span": None},
        }
    )
    return term


def _predicate_to_stitch(module, predicate, program_id, semantic_nodes):
    params = " ".join(
        "(Param {} {})".format(_symbol(param.type, "type"), _symbol(param.name, "param"))
        for param in predicate.params
    )
    role_target = _role_target(predicate)
    role = (
        "({} {})".format(_symbol(predicate.role, "role"), _symbol(role_target, "target"))
        if role_target
        else "({})".format(_symbol(predicate.role, "role"))
    )
    expr_term = _expr_to_stitch(predicate.expression)
    term = "(Predicate {} (Role {}) (Hash {}) (Params {}) (Expr {}))".format(
        _symbol(predicate.name, "predicate"),
        role,
        _hash_token(predicate.source_hash, "PH"),
        params,
        expr_term,
    )
    semantic_nodes.append(
        {
            "id": "{}:predicate:{}:{}".format(program_id, module.name, predicate.name),
            "kind": "Predicate",
            "role": predicate.role,
            "name": predicate.name,
            "target": role_target or "",
            "term": term,
            "source_hash": predicate.source_hash,
            "source": {"path": "", "span": None},
        }
    )
    return term


def _flow_to_stitch(module, program_id, semantic_nodes):
    term = "(Flow {} {} {} {})".format(
        _symbol(module.framework, "framework"),
        _symbol(module.kind, "flowkind"),
        _symbol(module.config, "config"),
        _symbol(module.name, "flow"),
    )
    semantic_nodes.append(
        {
            "id": "{}:flow:{}".format(program_id, module.name),
            "kind": "Flow",
            "role": module.kind,
            "name": module.name,
            "target": module.expression,
            "term": term,
            "source_hash": "",
            "source": {"path": "", "span": None},
        }
    )
    return term


def _path_query_to_stitch(path_query, program_id, semantic_nodes):
    variables = " ".join(
        "(PathVar {} {})".format(_symbol(var.type, "type"), _symbol(var.name, "var"))
        for var in path_query.variables
    )
    term = "(PathQuery (Vars {}) (FlowModule {}) (FlowPath {} {}) (Select {}))".format(
        variables,
        _symbol(path_query.flow_module, "flow"),
        _symbol(path_query.source_var, "source"),
        _symbol(path_query.sink_var, "sink"),
        _expr_to_stitch(path_query.select),
    )
    semantic_nodes.append(
        {
            "id": "{}:path-query".format(program_id),
            "kind": "PathQuery",
            "role": "PathProblem",
            "name": path_query.flow_module,
            "target": path_query.message,
            "term": term,
            "source_hash": _hash_token(path_query.message, "MSG"),
            "source": {"path": "", "span": None},
        }
    )
    return term


def _expr_to_stitch(node):
    kind = node["kind"]
    if kind == "var":
        return "(Var {})".format(_symbol(node["name"], "var"))
    if kind == "string":
        return "(String {})".format(_symbol(node["value"], "string"))
    if kind == "int":
        return "(Int {})".format(int(node["value"]))
    if kind == "exists":
        variables = " ".join(
            "(VarDecl {} {})".format(_symbol(var["type"], "type"), _symbol(var["name"], "var"))
            for var in node["vars"]
        )
        return "(Exists (Vars {}) (Body {}))".format(variables, _expr_to_stitch(node["body"]))
    if kind in {"and", "or"}:
        label = "And" if kind == "and" else "Or"
        return "({} {})".format(label, " ".join(_expr_to_stitch(term) for term in node["terms"]))
    if kind == "eq":
        return "(Eq {} {})".format(_expr_to_stitch(node["left"]), _expr_to_stitch(node["right"]))
    if kind == "qualified_call":
        return "(QualifiedCall {} {} (Args {}))".format(
            _symbol(node["namespace"], "namespace"),
            _symbol(node["name"], "call"),
            " ".join(_expr_to_stitch(arg) for arg in node.get("args", [])),
        )
    if kind == "method_call":
        return "(MethodCall {} {} (Args {}))".format(
            _expr_to_stitch(node["receiver"]),
            _symbol(node["method"], "method"),
            " ".join(_expr_to_stitch(arg) for arg in node.get("args", [])),
        )
    if kind == "argument_selection":
        return "(ArgumentSelection {} {})".format(_expr_to_stitch(node["receiver"]), node["index"])
    if kind == "qualified_name_check":
        return "(QualifiedNameCheck {} (QName {}))".format(
            _expr_to_stitch(node["receiver"]),
            _symbol("_".join(node["name_parts"]), "qname"),
        )
    if kind == "predicate_call":
        return "(PredicateCall {} (Args {}))".format(
            _symbol(node["name"], "predicate"),
            " ".join(_expr_to_stitch(arg) for arg in node.get("args", [])),
        )
    if kind == "path_select":
        return "(PathSelect {} {} {} (Message {}))".format(
            _expr_to_stitch(node["node"]),
            _expr_to_stitch(node["source"]),
            _expr_to_stitch(node["sink"]),
            _hash_token(node["message"], "MSG"),
        )
    raise ValueError("unsupported SQIR expression kind {}".format(kind))


def _module_to_fcir(module):
    predicates = " ".join(_predicate_to_fcir(predicate) for predicate in module.predicates)
    return "(ConfigModule {} {} (Predicates {}))".format(
        _atom(module.name), _atom(module.signature), predicates
    )


def _predicate_to_fcir(predicate):
    params = " ".join(
        "(Param {} {})".format(_atom(param.type), _atom(param.name))
        for param in predicate.params
    )
    role_target = _role_target(predicate)
    role = (
        "({} {})".format(predicate.role, _atom(role_target))
        if role_target
        else "({})".format(predicate.role)
    )
    return "(Predicate {} (Role {}) (Hash {}) (Params {}) (Expr {}))".format(
        _atom(predicate.name),
        role,
        _atom(predicate.source_hash),
        params,
        _expr_to_fcir(predicate.expression),
    )


def _flow_to_fcir(module):
    return "(Flow {} {} {} {})".format(
        _atom(module.framework),
        _atom(module.kind),
        _atom(module.config),
        _atom(module.name),
    )


def _path_query_to_fcir(path_query):
    variables = " ".join(
        "(PathVar {} {})".format(_atom(var.type), _atom(var.name))
        for var in path_query.variables
    )
    return "(PathQuery (Vars {}) (FlowModule {}) (SourceVar {}) (SinkVar {}) (Select {}))".format(
        variables,
        _atom(path_query.flow_module),
        _atom(path_query.source_var),
        _atom(path_query.sink_var),
        _expr_to_fcir(path_query.select),
    )


def _expr_to_fcir(node):
    kind = node["kind"]
    if kind == "var":
        return "(Var {})".format(_atom(node["name"]))
    if kind == "string":
        return "(String {})".format(_atom(node["value"]))
    if kind == "int":
        return "(Int {})".format(node["value"])
    if kind == "exists":
        variables = " ".join(
            "(VarDecl {} {})".format(_atom(var["type"]), _atom(var["name"]))
            for var in node["vars"]
        )
        return "(Exists (Vars {}) (Body {}))".format(
            variables, _expr_to_fcir(node["body"])
        )
    if kind in {"and", "or"}:
        label = "And" if kind == "and" else "Or"
        return "({} {})".format(
            label, " ".join(_expr_to_fcir(term) for term in node["terms"])
        )
    if kind == "eq":
        return "(Eq {} {})".format(
            _expr_to_fcir(node["left"]), _expr_to_fcir(node["right"])
        )
    if kind == "qualified_call":
        return "(QualifiedCall {} {} (Args {}))".format(
            _atom(node["namespace"]),
            _atom(node["name"]),
            " ".join(_expr_to_fcir(arg) for arg in node.get("args", [])),
        )
    if kind == "method_call":
        return "(MethodCall {} {} (Args {}))".format(
            _expr_to_fcir(node["receiver"]),
            _atom(node["method"]),
            " ".join(_expr_to_fcir(arg) for arg in node.get("args", [])),
        )
    if kind == "argument_selection":
        return "(ArgumentSelection {} {})".format(
            _expr_to_fcir(node["receiver"]), node["index"]
        )
    if kind == "qualified_name_check":
        return "(QualifiedNameCheck {} (Name {}))".format(
            _expr_to_fcir(node["receiver"]),
            " ".join(_atom(part) for part in node["name_parts"]),
        )
    if kind == "predicate_call":
        return "(PredicateCall {} (Args {}))".format(
            _atom(node["name"]),
            " ".join(_expr_to_fcir(arg) for arg in node.get("args", [])),
        )
    if kind == "path_select":
        return "(PathSelect {} {} {} {})".format(
            _expr_to_fcir(node["node"]),
            _expr_to_fcir(node["source"]),
            _expr_to_fcir(node["sink"]),
            _atom(node["message"]),
        )
    raise ValueError("unsupported SQIR expression kind {}".format(kind))


def _module_from_fcir(node):
    predicates_node = _child(node, "Predicates")
    return ConfigModule(
        name=node[1],
        signature=node[2],
        predicates=[
            _predicate_from_fcir(item)
            for item in predicates_node[1:]
            if item and item[0] == "Predicate"
        ],
    )


def _predicate_from_fcir(node):
    role_node = _child(node, "Role")[1]
    hash_node = _child(node, "Hash")
    params_node = _child(node, "Params")
    expr_node = _child(node, "Expr")
    return Predicate(
        name=node[1],
        role=role_node[0],
        source_hash=hash_node[1],
        params=[
            Param(type=item[1], name=item[2])
            for item in params_node[1:]
            if item and item[0] == "Param"
        ],
        expression=_expr_from_fcir(expr_node[1]),
    )


def _path_query_from_fcir(node):
    vars_node = _child(node, "Vars")
    select_node = _child(node, "Select")
    return PathQuery(
        variables=[
            PathVariable(type=item[1], name=item[2])
            for item in vars_node[1:]
            if item and item[0] == "PathVar"
        ],
        flow_module=_child(node, "FlowModule")[1],
        source_var=_child(node, "SourceVar")[1],
        sink_var=_child(node, "SinkVar")[1],
        select=_expr_from_fcir(select_node[1]),
        message=_expr_from_fcir(select_node[1]).get("message", ""),
    )


def _expr_from_fcir(node):
    label = node[0]
    if label == "Var":
        return {"kind": "var", "name": node[1]}
    if label == "String":
        return {"kind": "string", "value": node[1]}
    if label == "Int":
        return {"kind": "int", "value": int(node[1])}
    if label == "Exists":
        vars_node = _child(node, "Vars")
        body_node = _child(node, "Body")
        return {
            "kind": "exists",
            "vars": [
                {"type": item[1], "name": item[2]}
                for item in vars_node[1:]
                if item and item[0] == "VarDecl"
            ],
            "body": _expr_from_fcir(body_node[1]),
        }
    if label in {"And", "Or"}:
        return {
            "kind": label.lower(),
            "terms": [_expr_from_fcir(item) for item in node[1:]],
        }
    if label == "Eq":
        return {"kind": "eq", "left": _expr_from_fcir(node[1]), "right": _expr_from_fcir(node[2])}
    if label == "QualifiedCall":
        return {
            "kind": "qualified_call",
            "namespace": node[1],
            "name": node[2],
            "args": [_expr_from_fcir(item) for item in _child(node, "Args")[1:]],
        }
    if label == "MethodCall":
        return {
            "kind": "method_call",
            "receiver": _expr_from_fcir(node[1]),
            "method": node[2],
            "args": [_expr_from_fcir(item) for item in _child(node, "Args")[1:]],
        }
    if label == "ArgumentSelection":
        return {
            "kind": "argument_selection",
            "receiver": _expr_from_fcir(node[1]),
            "index": int(node[2]),
        }
    if label == "QualifiedNameCheck":
        return {
            "kind": "qualified_name_check",
            "receiver": _expr_from_fcir(node[1]),
            "name_parts": _child(node, "Name")[1:],
        }
    if label == "PredicateCall":
        return {
            "kind": "predicate_call",
            "name": node[1],
            "args": [_expr_from_fcir(item) for item in _child(node, "Args")[1:]],
        }
    if label == "PathSelect":
        return {
            "kind": "path_select",
            "node": _expr_from_fcir(node[1]),
            "source": _expr_from_fcir(node[2]),
            "sink": _expr_from_fcir(node[3]),
            "message": node[4],
        }
    raise ValueError("unsupported FCIR expression node {}".format(label))


def parse_sexpr(program):
    tokens = _tokenize(program)
    node, index = _parse_tokens(tokens, 0)
    if index != len(tokens):
        raise ValueError("trailing FCIR tokens")
    return node


def _tokenize(program):
    tokens = []
    for match in re.finditer(r'\s*([()]|"(?:\\.|[^"])*"|[^()\s]+)', program):
        token = match.group(1)
        if token.startswith('"'):
            tokens.append(bytes(token[1:-1], "utf-8").decode("unicode_escape"))
        else:
            tokens.append(token)
    return tokens


def _parse_tokens(tokens, index):
    if tokens[index] != "(":
        return tokens[index], index + 1
    result = []
    index += 1
    while index < len(tokens) and tokens[index] != ")":
        item, index = _parse_tokens(tokens, index)
        result.append(item)
    if index >= len(tokens):
        raise ValueError("unclosed FCIR list")
    return result, index + 1


def _sections(items):
    return {item[0]: item for item in items if isinstance(item, list) and item}


def _child(node, name):
    for item in node:
        if isinstance(item, list) and item and item[0] == name:
            return item
    raise ValueError("missing FCIR child {}".format(name))


def _role_target(predicate):
    if predicate.role == "Source":
        return _sourcenode_kind(predicate.expression) or _first_exists_type(predicate.expression)
    if predicate.role == "Sink":
        return (
            _sinknode_kind(predicate.expression)
            or _semantic_exists_type(predicate.expression)
            or _qualified_name_target(predicate.expression)
            or _method_name_set_target(predicate.expression)
            or _first_call_name(predicate.expression)
        )
    if predicate.role == "Barrier":
        return _barriernode_kind(predicate.expression) or _first_exists_type(predicate.expression)
    return None


GENERIC_CODEQL_TYPES = {
    "Callable",
    "Class",
    "Expr",
    "Field",
    "Method",
    "MethodAccess",
    "MethodCall",
    "Type",
    "Variable",
}


def _first_exists_type(node):
    if node.get("kind") == "exists" and node.get("vars"):
        return node["vars"][0]["type"]
    for child in _expr_children(node):
        found = _first_exists_type(child)
        if found:
            return found
    return None


def _semantic_exists_type(node):
    found = _first_exists_type(node)
    if found and found not in GENERIC_CODEQL_TYPES:
        return found
    return None


def _sinknode_kind(node):
    if node.get("kind") == "predicate_call" and node.get("name") == "sinkNode":
        for arg in node.get("args", []):
            if arg.get("kind") == "string":
                return "sinkNode:{}".format(arg.get("value", ""))
    for child in _expr_children(node):
        found = _sinknode_kind(child)
        if found:
            return found
    return None


def _sourcenode_kind(node):
    if node.get("kind") == "predicate_call" and node.get("name") == "sourceNode":
        for arg in node.get("args", []):
            if arg.get("kind") == "string":
                return "sourceNode:{}".format(arg.get("value", ""))
    for child in _expr_children(node):
        found = _sourcenode_kind(child)
        if found:
            return found
    return None


def _barriernode_kind(node):
    if node.get("kind") == "predicate_call" and node.get("name") == "barrierNode":
        for arg in node.get("args", []):
            if arg.get("kind") == "string":
                return "barrierNode:{}".format(arg.get("value", ""))
    for child in _expr_children(node):
        found = _barriernode_kind(child)
        if found:
            return found
    return None


def _qualified_name_target(node):
    if node.get("kind") == "qualified_name_check":
        return ".".join(node.get("name_parts", []))
    for child in _expr_children(node):
        found = _qualified_name_target(child)
        if found:
            return found
    return None


def _method_name_set_target(node):
    names = sorted(set(_method_has_names(node)))
    if names:
        return "method-names:{}".format("|".join(names))
    return None


def _method_has_names(node):
    names = []
    if (
        node.get("kind") == "method_call"
        and node.get("method") == "hasName"
        and node.get("args")
    ):
        for arg in node.get("args", []):
            if arg.get("kind") == "string":
                names.append(arg.get("value", ""))
    for child in _expr_children(node):
        names.extend(_method_has_names(child))
    return names


def _first_call_name(node):
    kind = node.get("kind")
    if kind == "qualified_name_check":
        return ".".join(node.get("name_parts", []))
    if kind == "method_call":
        return node.get("method")
    if kind == "argument_selection":
        return "argument{}".format(node.get("index"))
    for child in _expr_children(node):
        found = _first_call_name(child)
        if found:
            return found
    return None


def _expr_children(node):
    children = []
    for value in node.values():
        if isinstance(value, dict) and "kind" in value:
            children.append(value)
        elif isinstance(value, list):
            children.extend(item for item in value if isinstance(item, dict) and "kind" in item)
    return children


def _cwe_for_query(query):
    text = " ".join([query.metadata.get("id", ""), query.metadata.get("tags", "")])
    match = re.search(r"cwe[-/](\d+)|cwe-(\d+)", text, re.IGNORECASE)
    if match:
        return int(next(group for group in match.groups() if group))
    return None
