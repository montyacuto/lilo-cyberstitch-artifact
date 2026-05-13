import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional


SQIR_VERSION = "sqir-v2"


@dataclass
class Param:
    type: str
    name: str


@dataclass
class Predicate:
    name: str
    params: List[Param]
    role: str
    expression: Dict
    source_hash: str


@dataclass
class ConfigModule:
    name: str
    signature: str
    predicates: List[Predicate] = field(default_factory=list)


@dataclass
class FlowModule:
    name: str
    framework: str
    kind: str
    config: str

    @property
    def expression(self):
        return "{}::{}<{}>".format(self.framework, self.kind, self.config)


@dataclass
class PathVariable:
    type: str
    name: str


@dataclass
class PathQuery:
    variables: List[PathVariable]
    flow_module: str
    source_var: str
    sink_var: str
    select: Dict
    message: str


@dataclass
class Query:
    source_path: str
    language: str
    metadata: Dict[str, str]
    imports: List[str]
    config_modules: List[ConfigModule]
    flow_modules: List[FlowModule]
    path_query: PathQuery
    provenance_hash: str = ""
    version: str = SQIR_VERSION

    def validate(self):
        if self.version != SQIR_VERSION:
            raise ValueError("{}: unsupported SQIR version {}".format(self.source_path, self.version))
        if "name" not in self.metadata:
            raise ValueError("{}: missing @name metadata".format(self.source_path))
        if self.metadata.get("kind") != "path-problem":
            raise ValueError("{}: only path-problem queries are supported".format(self.source_path))
        if not self.imports:
            raise ValueError("{}: missing imports".format(self.source_path))
        if not self.config_modules:
            raise ValueError("{}: missing config module".format(self.source_path))
        if not self.flow_modules:
            raise ValueError("{}: missing flow module".format(self.source_path))

        for module in self.config_modules:
            names = {predicate.name for predicate in module.predicates}
            roles = {predicate.role for predicate in module.predicates}
            for required in ("isSource", "isSink"):
                if required not in names:
                    raise ValueError(
                        "{}: {} missing {}".format(self.source_path, module.name, required)
                    )
            if "Source" not in roles or "Sink" not in roles:
                raise ValueError(
                    "{}: {} missing source/sink semantic roles".format(
                        self.source_path, module.name
                    )
                )
            for predicate in module.predicates:
                _validate_predicate(predicate, self.source_path)

        flow_names = {flow.name for flow in self.flow_modules}
        if self.path_query.flow_module not in flow_names:
            raise ValueError(
                "{}: path query references unknown flow module {}".format(
                    self.source_path, self.path_query.flow_module
                )
            )
        if {self.path_query.source_var, self.path_query.sink_var} - {
            var.name for var in self.path_query.variables
        }:
            raise ValueError("{}: path query has unbound path variables".format(self.source_path))
        if self.path_query.select.get("kind") != "path_select":
            raise ValueError("{}: malformed path-query select clause".format(self.source_path))

    def to_dict(self):
        return asdict(self)

    def stable_hash(self):
        payload = self.to_dict()
        payload.pop("source_path", None)
        payload.pop("provenance_hash", None)
        text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(text.encode("utf-8")).hexdigest()


def query_from_dict(data):
    return Query(
        version=data.get("version", SQIR_VERSION),
        source_path=data["source_path"],
        language=data.get("language", _infer_language(data.get("imports", []))),
        metadata=data["metadata"],
        imports=data["imports"],
        config_modules=[
            ConfigModule(
                name=module["name"],
                signature=module["signature"],
                predicates=[
                    Predicate(
                        name=predicate["name"],
                        params=[Param(**param) for param in predicate["params"]],
                        role=predicate.get("role", _role_for_predicate(predicate["name"])),
                        expression=predicate["expression"],
                        source_hash=predicate.get("source_hash", ""),
                    )
                    for predicate in module["predicates"]
                ],
            )
            for module in data["config_modules"]
        ],
        flow_modules=[
            FlowModule(
                name=module["name"],
                framework=module["framework"],
                kind=module["kind"],
                config=module["config"],
            )
            for module in data["flow_modules"]
        ],
        path_query=PathQuery(
            variables=[PathVariable(**var) for var in data["path_query"]["variables"]],
            flow_module=data["path_query"]["flow_module"],
            source_var=data["path_query"]["source_var"],
            sink_var=data["path_query"]["sink_var"],
            select=data["path_query"]["select"],
            message=data["path_query"].get("message", ""),
        ),
        provenance_hash=data.get("provenance_hash", ""),
    )


def expr(kind, **values):
    node = {"kind": kind}
    node.update(values)
    return node


def stable_source_hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _validate_predicate(predicate, source_path):
    if predicate.role not in {"Source", "Sink", "Barrier", "Helper", "Other"}:
        raise ValueError(
            "{}: unsupported predicate role {} on {}".format(
                source_path, predicate.role, predicate.name
            )
        )
    scope = {param.name for param in predicate.params}
    _validate_expr(predicate.expression, scope, source_path)


def _validate_expr(node, scope, source_path):
    kind = node.get("kind")
    if kind == "var":
        if node["name"] not in scope:
            raise ValueError("{}: unbound variable {}".format(source_path, node["name"]))
    elif kind in {"string", "int", "type_ref"}:
        return
    elif kind == "exists":
        local = set(scope)
        for variable in node.get("vars", []):
            if not variable.get("name") or not variable.get("type"):
                raise ValueError("{}: malformed exists variable".format(source_path))
            local.add(variable["name"])
        _validate_expr(node["body"], local, source_path)
    elif kind in {"and", "or"}:
        terms = node.get("terms", [])
        if len(terms) < 2:
            raise ValueError("{}: {} expression needs at least two terms".format(source_path, kind))
        for term in terms:
            _validate_expr(term, scope, source_path)
    elif kind == "eq":
        _validate_expr(node["left"], scope, source_path)
        _validate_expr(node["right"], scope, source_path)
    elif kind == "qualified_call":
        for arg in node.get("args", []):
            _validate_expr(arg, scope, source_path)
    elif kind == "method_call":
        _validate_expr(node["receiver"], scope, source_path)
        for arg in node.get("args", []):
            _validate_expr(arg, scope, source_path)
    elif kind == "argument_selection":
        _validate_expr(node["receiver"], scope, source_path)
    elif kind == "qualified_name_check":
        _validate_expr(node["receiver"], scope, source_path)
    elif kind == "predicate_call":
        for arg in node.get("args", []):
            _validate_expr(arg, scope, source_path)
    else:
        raise ValueError("{}: unsupported SQIR expression kind {}".format(source_path, kind))


def _role_for_predicate(name):
    role = {
        "isSource": "Source",
        "isSink": "Sink",
        "isBarrier": "Barrier",
        "isSanitizer": "Barrier",
    }.get(name)
    return role or "Helper"


def _infer_language(imports):
    if "java" in imports:
        return "java"
    if "javascript" in imports:
        return "javascript"
    return "unknown"
