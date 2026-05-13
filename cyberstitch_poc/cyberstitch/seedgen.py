import json
import re
from pathlib import Path


SEED_MANIFEST_FORMAT = "cyberstitch-bounded-java-seed-manifest-v1"
GENERATED_PROFILE_FORMAT = "cyberstitch-generated-seed-profile-v1"

SUPPORTED_EXPRESSION_KINDS = {
    "exists_type",
    "model_label",
    "method_qualified_arg0",
    "method_name_arg0",
    "method_names_arg0",
    "argument_to_exec",
}

DEFAULT_IMPORTS = [
    "java",
    "semmle.code.java.dataflow.TaintTracking",
    "semmle.code.java.dataflow.FlowSources",
    "semmle.code.java.dataflow.ExternalFlow",
    "semmle.code.java.security.CommandLineQuery",
    "semmle.code.java.security.ExternalProcess",
    "semmle.code.java.security.QueryInjection",
    "semmle.code.java.security.SqlInjectionQuery",
    "semmle.code.java.security.Sanitizers",
    "semmle.code.java.security.TaintedEnvironmentVariableQuery",
]


def generate_seed_profile(manifest_path, output_dir):
    manifest_path = Path(manifest_path)
    output_dir = Path(output_dir)
    manifest = json.loads(manifest_path.read_text())
    validation = validate_seed_manifest(manifest)
    if not validation["ok"]:
        raise ValueError("invalid seed manifest: {}".format("; ".join(validation["errors"])))

    java_dir = output_dir / "java"
    java_dir.mkdir(parents=True, exist_ok=True)
    for path in java_dir.glob("*.ql"):
        path.unlink()

    imports = manifest.get("defaults", {}).get("imports") or DEFAULT_IMPORTS
    written = []
    for seed in manifest["seeds"]:
        query_text = render_seed_query(seed, imports)
        path = java_dir / "{}.ql".format(seed["id"])
        path.write_text(query_text)
        written.append(str(path))

    qlpack = java_dir / "qlpack.yml"
    qlpack.write_text(
        "name: cyberstitch/bounded-java-generated-queries\n"
        "version: 0.0.1\n"
        "dependencies:\n"
        "  codeql/java-all: \"*\"\n"
    )

    summary = {
        "format": GENERATED_PROFILE_FORMAT,
        "source_manifest": str(manifest_path.resolve()),
        "output_dir": str(output_dir.resolve()),
        "language": "java",
        "seeds": len(manifest["seeds"]),
        "queries": written,
        "selection_policy": manifest.get("selection_policy", ""),
        "target_validated_candidates": manifest.get("target_validated_candidates", {}),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "seed-generation-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (output_dir / "seed_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return summary


def validate_seed_manifest(manifest):
    errors = []
    if manifest.get("format") != SEED_MANIFEST_FORMAT:
        errors.append("unsupported format")
    if manifest.get("language", "java") != "java":
        errors.append("only Java seed manifests are supported")
    seeds = manifest.get("seeds")
    if not isinstance(seeds, list) or not seeds:
        errors.append("missing seeds")
        seeds = []

    seen = set()
    for index, seed in enumerate(seeds):
        prefix = "seed[{}]".format(index)
        seed_id = seed.get("id", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", seed_id):
            errors.append("{} invalid id {}".format(prefix, seed_id))
        if seed_id in seen:
            errors.append("{} duplicate id {}".format(prefix, seed_id))
        seen.add(seed_id)
        if int(seed.get("cwe", 0) or 0) not in {78, 89}:
            errors.append("{} unsupported cwe {}".format(prefix, seed.get("cwe")))
        for role in ["source", "sink"]:
            if role not in seed:
                errors.append("{} missing {}".format(prefix, role))
            else:
                errors.extend(_expression_errors(seed[role], "{}.{}".format(prefix, role), role))
        if "barrier" in seed and seed["barrier"] is not None:
            errors.extend(_expression_errors(seed["barrier"], "{}.barrier".format(prefix), "barrier"))
    return {"ok": not errors, "errors": errors, "seeds": len(seeds)}


def render_seed_query(seed, imports):
    seed_id = seed["id"]
    module_stem = _camel(seed_id)
    config_name = "{}Config".format(module_stem)
    flow_name = "{}Flow".format(module_stem)
    cwe = int(seed["cwe"])
    metadata_id = "java/cyberstitch/bounded/{}".format(seed_id)
    source_expr = render_expression(seed["source"], "source", "Source")
    sink_expr = render_expression(seed["sink"], "sink", "Sink")
    barrier = seed.get("barrier")
    barrier_expr = render_expression(barrier, "node", "Barrier") if barrier else None
    message = seed.get("message") or "{} source reaches {} sink.".format(
        _target_text(seed["source"]), _target_text(seed["sink"])
    )

    lines = [
        "/**",
        " * @name {}".format(seed.get("name", seed_id.replace("-", " ").title())),
        " * @kind path-problem",
        " * @problem.severity error",
        " * @id {}".format(metadata_id),
        " * @tags security external/cwe/cwe-{:03d}".format(cwe),
        " */",
        "",
    ]
    for import_name in imports:
        lines.append("import {}".format(import_name))
    lines.extend(
        [
            "",
            "module {} implements DataFlow::ConfigSig {{".format(config_name),
            "  predicate isSource(DataFlow::Node source) {",
        ]
    )
    lines.extend(_indent_expression(source_expr, 4))
    lines.extend(
        [
            "  }",
            "",
            "  predicate isSink(DataFlow::Node sink) {",
        ]
    )
    lines.extend(_indent_expression(sink_expr, 4))
    lines.append("  }")
    if barrier_expr:
        lines.extend(
            [
                "",
                "  predicate isBarrier(DataFlow::Node node) {",
            ]
        )
        lines.extend(_indent_expression(barrier_expr, 4))
        lines.append("  }")
    lines.extend(
        [
            "}",
            "",
            "module {} = TaintTracking::Global<{}>;".format(flow_name, config_name),
            "import {}::PathGraph".format(flow_name),
            "",
            "from {}::PathNode source, {}::PathNode sink".format(flow_name, flow_name),
            "where {}::flowPath(source, sink)".format(flow_name),
            "select sink.getNode(), source, sink, {}".format(_ql_string(message)),
            "",
        ]
    )
    return "\n".join(lines)


def render_expression(spec, parameter_name, role):
    if not spec:
        raise ValueError("missing {} expression".format(role.lower()))
    kind = spec.get("kind")
    if kind == "exists_type":
        variable = spec.get("var") or _default_var(spec["type"])
        return "exists({type} {var} | {param} = {var})".format(
            type=spec["type"], var=variable, param=parameter_name
        )
    if kind == "model_label":
        predicate = spec.get("predicate") or {
            "Source": "sourceNode",
            "Sink": "sinkNode",
            "Barrier": "barrierNode",
        }[role]
        return "{}({}, {})".format(predicate, parameter_name, _ql_string(spec["label"]))
    if kind == "method_qualified_arg0":
        return (
            "exists(MethodCall call |\n"
            "  call.getMethod().hasQualifiedName({}, {}, {}) and\n"
            "  {}.asExpr() = call.getArgument(0)\n"
            ")"
        ).format(
            _ql_string(spec["package"]),
            _ql_string(spec["type"]),
            _ql_string(spec["method"]),
            parameter_name,
        )
    if kind == "method_name_arg0":
        return (
            "exists(MethodCall call |\n"
            "  call.getMethod().hasName({}) and\n"
            "  {}.asExpr() = call.getArgument(0)\n"
            ")"
        ).format(_ql_string(spec["name"]), parameter_name)
    if kind == "method_names_arg0":
        terms = []
        for name in spec.get("names", []):
            terms.append(
                "call.getMethod().hasName({}) and\n"
                "  {}.asExpr() = call.getArgument(0)".format(_ql_string(name), parameter_name)
            )
        return "exists(MethodCall call |\n  {}\n)".format("\n  or\n  ".join(terms))
    if kind == "argument_to_exec":
        variable = spec.get("var", "command")
        return (
            "exists(CommandInjectionSink {var} |\n"
            "  argumentToExec({param}.asExpr(), {var})\n"
            ")"
        ).format(var=variable, param=parameter_name)
    raise ValueError("unsupported {} expression kind {}".format(role.lower(), kind))


def _expression_errors(spec, prefix, role):
    errors = []
    if not isinstance(spec, dict):
        return ["{} must be an object".format(prefix)]
    kind = spec.get("kind")
    if kind not in SUPPORTED_EXPRESSION_KINDS:
        errors.append("{} unsupported kind {}".format(prefix, kind))
        return errors
    required = {
        "exists_type": ["type"],
        "model_label": ["label"],
        "method_qualified_arg0": ["package", "type", "method"],
        "method_name_arg0": ["name"],
        "method_names_arg0": ["names"],
        "argument_to_exec": [],
    }[kind]
    for field in required:
        if not spec.get(field):
            errors.append("{} missing {}".format(prefix, field))
    if kind.startswith("method") and role != "sink":
        errors.append("{} method sink expressions are only valid for sinks".format(prefix))
    if kind == "argument_to_exec" and role != "sink":
        errors.append("{} argument_to_exec is only valid for sinks".format(prefix))
    if kind == "method_names_arg0" and not isinstance(spec.get("names"), list):
        errors.append("{} names must be a list".format(prefix))
    return errors


def _indent_expression(expression, spaces):
    pad = " " * spaces
    return [pad + line for line in expression.splitlines()]


def _ql_string(value):
    return '"{}"'.format(str(value).replace("\\", "\\\\").replace('"', '\\"'))


def _camel(value):
    parts = re.split(r"[^A-Za-z0-9]+", value)
    text = "".join(part[:1].upper() + part[1:] for part in parts if part)
    if not text or text[0].isdigit():
        text = "Seed{}".format(text)
    return text


def _default_var(type_name):
    stem = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(type_name)).split("::")[-1]
    parts = [part for part in re.split(r"[^A-Za-z0-9]+", stem.lower()) if part]
    return parts[-1] if parts else "node"


def _target_text(spec):
    kind = spec.get("kind")
    if kind == "exists_type":
        return spec.get("type", "")
    if kind == "model_label":
        return "{}:{}".format(spec.get("predicate", "model"), spec.get("label", ""))
    if kind == "method_qualified_arg0":
        return "{}.{}.{}".format(spec.get("package", ""), spec.get("type", ""), spec.get("method", ""))
    if kind == "method_name_arg0":
        return spec.get("name", "")
    if kind == "method_names_arg0":
        return "|".join(spec.get("names", []))
    if kind == "argument_to_exec":
        return "argumentToExec"
    return kind or ""
