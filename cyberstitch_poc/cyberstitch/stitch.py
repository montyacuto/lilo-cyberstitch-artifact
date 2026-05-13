import json
import shutil
import subprocess
from pathlib import Path

from .abstractions import (
    candidates_from_stitch_item,
    exact_semantic_match,
    load_provenance,
    normalize_term,
    term_index,
)
from .parser import format_expression


STITCH_CORE_BRIDGE = r"""
import json
import sys

import stitch_core as stitch

programs_path, output_path = sys.argv[1], sys.argv[2]
iterations, max_arity, threads = [int(item) for item in sys.argv[3:6]]

with open(programs_path) as handle:
    programs = json.load(handle)
if not isinstance(programs, list) or not all(isinstance(item, str) for item in programs):
    raise TypeError("STITCH programs input must be a JSON array of program strings")

result = stitch.compress(
    programs=programs,
    iterations=iterations,
    max_arity=max_arity,
    threads=threads,
    silent=True,
    rewritten_intermediates=True,
)
with open(output_path, "w") as handle:
    json.dump(result.json, handle, indent=2)
"""


def run_stitch(
    mode,
    corpus_path,
    output_path,
    fixture_path,
    stitch_binary=None,
    stitch_python=None,
    provenance_path=None,
    iterations=3,
    max_arity=2,
    threads=1,
):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if mode == "offline":
        output_path.write_text(Path(fixture_path).read_text())
        return {"mode": "offline", "output": str(output_path)}

    raw_output_path = output_path.parent / "raw-stitch.json"
    if stitch_python:
        backend = "stitch_core"
        completed = _run_stitch_core_bridge(
            stitch_python,
            corpus_path,
            raw_output_path,
            iterations=iterations,
            max_arity=max_arity,
            threads=threads,
        )
    else:
        backend = "binary"
        completed = _run_stitch_binary(
            stitch_binary,
            corpus_path,
            raw_output_path,
        )

    if raw_output_path.exists():
        raw = json.loads(raw_output_path.read_text())
    else:
        try:
            raw = json.loads(completed.stdout)
            raw_output_path.write_text(json.dumps(raw, indent=2))
        except json.JSONDecodeError:
            raw = {"raw_stdout": completed.stdout}
            raw_output_path.write_text(json.dumps(raw, indent=2))

    candidates = _candidates_from_stitch(raw, provenance_path)
    output_path.write_text(json.dumps(candidates, indent=2))
    return {
        "mode": "live",
        "backend": backend,
        "input": str(corpus_path),
        "raw_output": str(raw_output_path),
        "output": str(output_path),
        "candidates": len(candidates.get("candidates", [])),
    }


def _run_stitch_core_bridge(stitch_python, corpus_path, raw_output_path, iterations, max_arity, threads):
    stitch_python = str(stitch_python)
    if not Path(stitch_python).exists():
        raise RuntimeError("STITCH Python interpreter not found: {}".format(stitch_python))
    completed = subprocess.run(
        [
            stitch_python,
            "-c",
            STITCH_CORE_BRIDGE,
            str(corpus_path),
            str(raw_output_path),
            str(iterations),
            str(max_arity),
            str(threads),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "LILO stitch_core bridge failed")
    return completed


def _run_stitch_binary(stitch_binary, corpus_path, raw_output_path):
    binary = stitch_binary or shutil.which("stitch") or shutil.which("compress")
    if not binary:
        raise RuntimeError(
            "No STITCH backend found; use --stitch-python for the LILO stitch_core bridge, "
            "--stitch-binary for a direct binary, or --mode offline."
        )
    completed = subprocess.run(
        [binary, str(corpus_path), "--out", str(raw_output_path), "--rewritten-intermediates"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "STITCH binary failed")
    return completed


def _candidates_from_stitch(raw, provenance_path=None):
    provenance = load_provenance(provenance_path)
    index = term_index(provenance)
    candidates = []
    for item in raw.get("abstractions", []):
        candidates.extend(candidates_from_stitch_item(item, provenance, index))
    return {
        "format": "cyberstitch-candidates-v2",
        "source": "stitch-live",
        "raw_num_abstractions": raw.get("num_abstractions", len(raw.get("abstractions", []))),
        "candidates": candidates,
    }


def _load_provenance(path):
    return load_provenance(path)


def _term_index(provenance):
    return term_index(provenance)


def _exact_semantic_match(body, term_index):
    return exact_semantic_match(body, term_index)


def _normalize_term(term):
    return normalize_term(term)


def _mapped_codeql_helper(stitch_item, mapped, provenance):
    predicate_name = _safe_predicate_name(stitch_item.get("name", "fn_0"))
    body = _codeql_body_for_mapping(predicate_name, mapped)
    return {
        "name": predicate_name,
        "kind": "codeql_helper",
        "language": mapped.get("language", "unknown"),
        "helper_module": "CyberStitchJavaHelpers" if mapped.get("language") == "java" else "CyberStitchHelpers",
        "predicate": predicate_name,
        "body": body,
        "use_sites": _use_sites_for_program(mapped, provenance),
        "mapping_status": "exact-term",
        "semantic_role": mapped.get("role", ""),
        "semantic_target": mapped.get("target", ""),
        "stitch": stitch_item,
    }


def _use_sites_for_program(mapped, provenance):
    sites = []
    for match in mapped.get("_matches", [mapped]):
        program = match.get("program", {})
        name = Path(program.get("name", "")).name
        for node in program.get("semantic_nodes", []):
            if node.get("id") == match.get("semantic_node_id"):
                sites.append({"query": name, "predicate": node.get("name", "")})
    return sites


def _codeql_body_for_mapping(predicate_name, mapped):
    predicate = _sqir_predicate_for_mapping(mapped)
    if not predicate:
        return "predicate {}() {{ none() }}".format(predicate_name)
    params = ", ".join(
        "{} {}".format(param["type"], param["name"])
        for param in predicate.get("params", [])
    )
    return "predicate {}({}) {{\n  {}\n}}".format(
        predicate_name,
        params,
        format_expression(predicate["expression"]),
    )


def _sqir_predicate_for_mapping(mapped):
    program = mapped.get("program", {})
    sqir = program.get("sqir") or {}
    semantic_id = mapped.get("semantic_node_id", "")
    parts = semantic_id.split(":")
    if len(parts) < 4 or parts[1] != "predicate":
        return None
    config_name, predicate_name = parts[2], parts[3]
    for module in sqir.get("config_modules", []):
        if module.get("name") != config_name:
            continue
        for predicate in module.get("predicates", []):
            if predicate.get("name") == predicate_name:
                return predicate
    return None


def _safe_predicate_name(name):
    text = "".join(char if char.isalnum() or char == "_" else "_" for char in str(name))
    text = text.strip("_") or "fn_0"
    if text[0].isdigit():
        text = "fn_{}".format(text)
    return text
