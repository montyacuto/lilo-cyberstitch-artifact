import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


AUTODOC_EVAL_FORMAT = "cyberstitch-autodoc-eval-v1"
AUTODOC_EVAL_FIXTURE_FORMAT = "cyberstitch-autodoc-eval-fixture-v1"
DEFAULT_SOURCE_RESULTS = "benchmarkjava_lilo_full_combined_pack_20260507"
PRIMARY_CONDITIONS = [
    "raw_names",
    "typed_names",
    "autodoc_names",
    "autodoc_docstrings",
]

LILO_AUTODOC_BRIDGE = r"""
import json
import sys

from src.openai_compat import create_completion, completion_to_dict

prompt_path, output_path, model, max_tokens, temperature = sys.argv[1:6]
prompt = open(prompt_path).read()
response = create_completion(
    model=model,
    prompt=None,
    messages=[{"role": "user", "content": prompt}],
    is_chat=True,
    temperature=float(temperature),
    top_p=1.0,
    n=1,
    stop=None,
    max_tokens=int(max_tokens),
)
data = completion_to_dict(response)
text = data["choices"][0].get("text", "")
with open(output_path, "w") as handle:
    json.dump({"response": data, "text": text}, handle, indent=2)
"""


def run_autodoc_eval(
    config,
    source_results=None,
    output_dir=None,
    mode="fixture",
    fixture_path=None,
    model="gpt-3.5-turbo",
    samples=3,
    lilo_python=None,
    cache_dir=None,
    include_provenance_rich=False,
    max_tokens=900,
    temperature=0.2,
):
    source_results = _resolve_source_results(config, source_results)
    output_dir = Path(output_dir or source_results / "autodoc-eval").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    samples = max(1, int(samples))

    inventory = build_inventory(source_results)
    tasks = build_tasks(inventory)
    conditions = build_conditions(inventory, include_provenance_rich=include_provenance_rich)
    fixture = _load_fixture(fixture_path) if mode == "fixture" else {}

    _write_json(output_dir / "inventory.json", {"format": AUTODOC_EVAL_FORMAT, "items": inventory})
    _write_json(output_dir / "conditions.json", {"format": AUTODOC_EVAL_FORMAT, "conditions": conditions})
    _write_json(output_dir / "tasks.json", {"format": AUTODOC_EVAL_FORMAT, "tasks": tasks})

    parsed_results = []
    responses_root = output_dir / "responses"
    prompts_root = output_dir / "prompts"
    for condition_name, presentation in conditions.items():
        for task in tasks:
            for sample_index in range(samples):
                prompt = render_prompt(condition_name, presentation, task, sample_index=sample_index)
                prompt_path = prompts_root / condition_name / task["id"] / "{}.txt".format(sample_index)
                prompt_path.parent.mkdir(parents=True, exist_ok=True)
                prompt_path.write_text(prompt)

                response_path = responses_root / condition_name / task["id"] / "{}.json".format(sample_index)
                response_path.parent.mkdir(parents=True, exist_ok=True)
                raw = _get_response(
                    mode=mode,
                    fixture=fixture,
                    condition_name=condition_name,
                    task=task,
                    inventory=inventory,
                    sample_index=sample_index,
                    prompt_path=prompt_path,
                    response_path=response_path,
                    model=model,
                    lilo_python=lilo_python,
                    cache_dir=cache_dir or _default_cache_dir(config),
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                _write_json(response_path, raw)
                parsed = parse_response(raw.get("text", ""))
                scored = score_task(task, parsed, inventory)
                parsed_results.append(
                    {
                        "condition": condition_name,
                        "task_id": task["id"],
                        "task_type": task["type"],
                        "sample_index": sample_index,
                        "prompt": str(prompt_path),
                        "response": str(response_path),
                        "parse": parsed,
                        "score": scored,
                    }
                )

    scores = aggregate_scores(parsed_results, conditions)
    summary = {
        "format": AUTODOC_EVAL_FORMAT,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_results": str(source_results),
        "output_dir": str(output_dir),
        "mode": mode,
        "model": model,
        "samples": samples,
        "conditions": list(conditions),
        "tasks": len(tasks),
        "inventory_items": len(inventory),
        "scores": scores,
        "primary_comparison": _primary_comparison(scores),
        "files": {
            "inventory": str(output_dir / "inventory.json"),
            "conditions": str(output_dir / "conditions.json"),
            "tasks": str(output_dir / "tasks.json"),
            "parsed": str(output_dir / "parsed.json"),
            "scores": str(output_dir / "scores.json"),
            "report": str(output_dir / "report.md"),
        },
    }
    _write_json(output_dir / "parsed.json", {"format": AUTODOC_EVAL_FORMAT, "results": parsed_results})
    _write_json(output_dir / "scores.json", {"format": AUTODOC_EVAL_FORMAT, "scores": scores})
    _write_json(output_dir / "summary.json", summary)
    (output_dir / "report.md").write_text(_write_report(summary, inventory, tasks))
    return summary


def build_inventory(source_results):
    source_results = Path(source_results)
    decisions_path = source_results / "validation" / "decisions.json"
    if not decisions_path.exists():
        raise RuntimeError("validation decisions not found: {}".format(decisions_path))
    docs = _load_autodoc(source_results / "lilo-loop" / "autodoc.json")
    data = _read_json(decisions_path)
    items = []
    for decision in data.get("decisions", []):
        if not decision.get("accepted_for_lilo", decision.get("accepted")):
            continue
        candidate = decision.get("candidate", {})
        if candidate.get("kind") not in {"codeql_helper", "semantic_template"}:
            continue
        name = candidate.get("name", "")
        if not name:
            continue
        item_id = "candidate:{}".format(name)
        autodoc = docs.get(item_id) or docs.get(name)
        autodoc_source = "lilo-loop-autodoc" if autodoc else "candidate"
        autodoc = autodoc or {}
        role = candidate.get("semantic_role") or _role_from_schema(candidate.get("schema", ""))
        item = {
            "id": item_id,
            "name": name,
            "raw_name": name,
            "typed_name": "{} [{} {}]".format(
                name,
                role or "Unknown",
                candidate.get("semantic_target", "") or candidate.get("schema", ""),
            ).strip(),
            "autodoc_name": autodoc.get("display_name") or candidate.get("display_name") or name,
            "autodoc_description": autodoc.get("description") or candidate.get("description", ""),
            "autodoc_rationale": autodoc.get("rationale") or candidate.get("rationale", ""),
            "autodoc_source": autodoc_source,
            "schema": candidate.get("schema", ""),
            "kind": candidate.get("kind", ""),
            "language": candidate.get("language", ""),
            "semantic_role": role,
            "semantic_target": candidate.get("semantic_target", ""),
            "semantic_hash": candidate.get("semantic_hash", ""),
            "predicate": candidate.get("predicate", ""),
            "helper_module": candidate.get("helper_module", ""),
            "rewrite_eligible": bool(candidate.get("rewrite_eligible")),
            "validation": {
                "accepted": bool(decision.get("accepted")),
                "accepted_for_lilo": True,
                "reasons": decision.get("reasons", []),
                "lilo_reasons": decision.get("lilo_reasons", []),
            },
            "group": _group_for_role(role),
            "use_sites": [
                {
                    "query": site.get("query", ""),
                    "predicate": site.get("predicate", ""),
                }
                for site in candidate.get("use_sites", [])[:8]
            ],
        }
        items.append(item)
    if not items:
        raise RuntimeError("no accepted LILO abstraction candidates found in {}".format(decisions_path))
    return sorted(items, key=lambda item: item["id"])


def build_conditions(inventory, include_provenance_rich=False):
    conditions = {
        "raw_names": [
            {
                "id": item["id"],
                "name": item["raw_name"],
            }
            for item in inventory
        ],
        "typed_names": [
            {
                "id": item["id"],
                "name": item["raw_name"],
                "schema": item["schema"],
                "semantic_role": item["semantic_role"],
                "semantic_target": item["semantic_target"],
            }
            for item in inventory
        ],
        "autodoc_names": [
            {
                "id": item["id"],
                "name": item["autodoc_name"],
                "autodoc_source": item["autodoc_source"],
            }
            for item in inventory
        ],
        "autodoc_docstrings": [
            {
                "id": item["id"],
                "name": item["autodoc_name"],
                "description": item["autodoc_description"],
                "rationale": item["autodoc_rationale"],
                "autodoc_source": item["autodoc_source"],
            }
            for item in inventory
        ],
    }
    if include_provenance_rich:
        conditions["provenance_rich"] = [
            {
                "id": item["id"],
                "name": item["autodoc_name"],
                "description": item["autodoc_description"],
                "schema": item["schema"],
                "semantic_role": item["semantic_role"],
                "semantic_target": item["semantic_target"],
                "predicate": item["predicate"],
                "use_sites": item["use_sites"],
            }
            for item in inventory
        ]
    return conditions


def build_tasks(inventory):
    by_id = {item["id"]: item for item in inventory}
    tasks = [
        {
            "id": "role_classification",
            "type": "role_classification",
            "instruction": "Classify every abstraction by semantic role. Use only Source, Sink, Barrier, FlowStep, or Other.",
            "expected_roles": {
                item["id"]: _normalize_role(item["semantic_role"])
                for item in inventory
            },
            "output_shape": {"roles": {"candidate:<name>": "Source|Sink|Barrier|FlowStep|Other"}},
        },
        {
            "id": "group_families",
            "type": "grouping",
            "instruction": "Group all abstractions into source, sink, and barrier families.",
            "expected_groups": _expected_groups(inventory),
            "output_shape": {
                "groups": {
                    "sources": ["candidate:<name>"],
                    "sinks": ["candidate:<name>"],
                    "barriers": ["candidate:<name>"],
                }
            },
        },
    ]
    selectors = [
        (
            "select_remote_source",
            "Select exactly one abstraction for Java remote user-controlled input source nodes.",
            "candidate:java_remote_flow_source",
        ),
        (
            "select_active_threat_source",
            "Select exactly one abstraction for active threat-model source nodes.",
            "candidate:java_active_threat_model_source",
        ),
        (
            "select_modeled_command_sink",
            "Select exactly one abstraction for CodeQL modeled command-injection sinks.",
            "candidate:java_command_injection_sink_sink",
        ),
        (
            "select_modeled_sql_sink",
            "Select exactly one abstraction for CodeQL modeled SQL/query-injection sinks.",
            "candidate:java_query_injection_sink_sink",
        ),
        (
            "select_runtime_exec_sink",
            "Select exactly one abstraction for direct java.lang.Runtime.exec argument sinks.",
            "candidate:java_java_lang_runtime_exec_sink",
        ),
        (
            "select_statement_execute_sink",
            "Select exactly one abstraction for method-name based Statement execute/query/update argument sinks.",
            "candidate:java_method_names_execute_execute_query_execute_update_sink",
        ),
        (
            "select_command_sanitizer",
            "Select exactly one abstraction for a command-injection sanitizer or barrier.",
            "candidate:java_command_injection_sanitizer_barrier",
        ),
    ]
    for task_id, instruction, expected in selectors:
        if expected in by_id:
            tasks.append(
                {
                    "id": task_id,
                    "type": "helper_selection",
                    "instruction": instruction,
                    "expected": [expected],
                    "output_shape": {"selected": ["candidate:<name>"]},
                }
            )
    if "candidate:java_remote_flow_source" in by_id:
        tasks.append(
            {
                "id": "rewrite_remote_source_reference",
                "type": "rewrite_reference",
                "instruction": "Return a rewrite_candidate_reference_v1 proposal for the remote user-input source helper.",
                "expected": ["candidate:java_remote_flow_source"],
                "output_shape": {
                    "proposals": [
                        {
                            "schema": "rewrite_candidate_reference_v1",
                            "candidate_ref": "candidate:<name>",
                        }
                    ]
                },
            }
        )
    runtime_sink = "candidate:java_java_lang_runtime_exec_sink"
    if runtime_sink in by_id:
        tasks.append(
            {
                "id": "reject_raw_codeql_for_runtime_exec",
                "type": "raw_codeql_rejection",
                "instruction": (
                    "Choose the existing helper for Runtime.exec sinks without writing "
                    "any CodeQL, QL predicate body, import, or select clause."
                ),
                "expected": [runtime_sink],
                "output_shape": {"selected": ["candidate:<name>"], "no_raw_codeql": True},
            }
        )
    return tasks


def render_prompt(condition_name, presentation, task, sample_index=0):
    payload = {
        "role": "You are evaluating reusable CodeQL security abstractions for a LILO reproduction artifact.",
        "condition": condition_name,
        "task_id": task["id"],
        "task_type": task["type"],
        "sample_index": sample_index,
        "instruction": task["instruction"],
        "constraints": [
            "Return one JSON object only.",
            "Do not return Markdown, headings, prose, or fenced code blocks.",
            "The top-level JSON keys must match the required output shape.",
            "Use only candidate ids from the provided abstraction inventory.",
            "Do not write CodeQL, QL predicate bodies, imports, select clauses, or source code.",
            "If the task asks for a rewrite candidate, use schema rewrite_candidate_reference_v1.",
        ],
        "required_output_shape": task["output_shape"],
        "abstractions": presentation,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def parse_response(text):
    parsed = {"ok": False, "data": None, "error": None, "text": text}
    try:
        parsed["data"] = _extract_json(text)
        parsed["ok"] = True
    except Exception as exc:
        parsed["error"] = "{}: {}".format(type(exc).__name__, exc)
    return parsed


def score_task(task, parsed, inventory):
    data = parsed.get("data") if parsed.get("ok") else None
    valid_ids = {item["id"] for item in inventory}
    alias_map = _candidate_aliases(inventory)
    raw_violation = _contains_raw_codeql(parsed.get("text", ""), data)
    references = _all_candidate_refs(data, alias_map)
    invalid_refs = sorted(ref for ref in references if ref not in valid_ids)
    base = {
        "parse_ok": bool(parsed.get("ok")),
        "raw_codeql_violation": raw_violation,
        "candidate_refs": sorted(references),
        "invalid_candidate_refs": invalid_refs,
        "candidate_references_valid": not invalid_refs,
        "score": 0.0,
        "success": False,
    }
    if not data:
        return base

    task_type = task["type"]
    if task_type == "role_classification":
        roles = data.get("roles") or data.get("classification")
        if roles is None and _looks_like_role_map(data, alias_map):
            roles = data
        roles = _canonical_role_map(roles or {}, alias_map)
        expected = task.get("expected_roles", {})
        correct = 0
        for candidate_id, role in expected.items():
            if _normalize_role(roles.get(candidate_id, "")) == _normalize_role(role):
                correct += 1
        score = correct / len(expected) if expected else 0.0
        base.update({"score": score, "success": score == 1.0, "correct": correct, "total": len(expected)})
    elif task_type in {"helper_selection", "rewrite_reference", "raw_codeql_rejection"}:
        selected = _selected_refs(data, alias_map)
        expected = set(task.get("expected", []))
        score = 1.0 if selected == expected else 0.0
        if task_type == "raw_codeql_rejection" and raw_violation:
            score = 0.0
        base.update(
            {
                "score": score,
                "success": score == 1.0,
                "selected": sorted(selected),
                "expected": sorted(expected),
            }
        )
    elif task_type == "grouping":
        expected = task.get("expected_groups", {})
        observed = _observed_groups(data, alias_map)
        f1s = []
        for group in ["sources", "sinks", "barriers"]:
            f1s.append(_set_f1(set(expected.get(group, [])), set(observed.get(group, []))))
        score = sum(f1s) / len(f1s) if f1s else 0.0
        base.update({"score": score, "success": score == 1.0, "group_f1": dict(zip(["sources", "sinks", "barriers"], f1s))})
    return base


def aggregate_scores(parsed_results, conditions):
    scores = {}
    for condition in conditions:
        items = [item for item in parsed_results if item["condition"] == condition]
        scores[condition] = _aggregate_condition(items)
    return scores


def _aggregate_condition(items):
    total = len(items)
    by_type = {}
    for item in items:
        by_type.setdefault(item["task_type"], []).append(item)
    refs_total = sum(len(item["score"].get("candidate_refs", [])) for item in items)
    refs_invalid = sum(len(item["score"].get("invalid_candidate_refs", [])) for item in items)
    return {
        "samples": total,
        "parse_rate": _rate(item["score"].get("parse_ok") for item in items),
        "task_success_rate": _rate(item["score"].get("success") for item in items),
        "aggregate_score": _mean(item["score"].get("score", 0.0) for item in items),
        "raw_codeql_violation_rate": _rate(item["score"].get("raw_codeql_violation") for item in items),
        "candidate_reference_valid_rate": 1.0 - (refs_invalid / refs_total if refs_total else 0.0),
        "role_accuracy": _mean(item["score"].get("score", 0.0) for item in by_type.get("role_classification", [])),
        "helper_selection_accuracy": _rate(item["score"].get("success") for item in by_type.get("helper_selection", [])),
        "rewrite_reference_rate": _rate(item["score"].get("success") for item in by_type.get("rewrite_reference", [])),
        "grouping_macro_f1": _mean(item["score"].get("score", 0.0) for item in by_type.get("grouping", [])),
        "raw_codeql_rejection_success_rate": _rate(item["score"].get("success") for item in by_type.get("raw_codeql_rejection", [])),
    }


def _get_response(
    mode,
    fixture,
    condition_name,
    task,
    inventory,
    sample_index,
    prompt_path,
    response_path,
    model,
    lilo_python,
    cache_dir,
    max_tokens,
    temperature,
):
    if mode == "fixture":
        return _fixture_response(fixture, condition_name, task, inventory, sample_index)
    return _run_lilo_bridge(
        mode=mode,
        prompt_path=prompt_path,
        output_path=response_path,
        model=model,
        lilo_python=lilo_python,
        cache_dir=cache_dir,
        max_tokens=max_tokens,
        temperature=temperature,
    )


def _run_lilo_bridge(mode, prompt_path, output_path, model, lilo_python, cache_dir, max_tokens, temperature):
    lilo_python = Path(lilo_python or _default_lilo_python())
    if not lilo_python.exists():
        raise RuntimeError("LILO Python interpreter not found: {}".format(lilo_python))
    lilo_root = lilo_python.parents[4]
    env = dict(os.environ)
    env["LILO_LLM_CACHE_MODE"] = "replay" if mode == "replay" else env.get("LILO_LLM_CACHE_MODE", "record")
    env["LILO_LLM_CACHE_DIR"] = str(Path(cache_dir).resolve())
    completed = subprocess.run(
        [
            str(lilo_python),
            "-c",
            LILO_AUTODOC_BRIDGE,
            str(prompt_path),
            str(output_path),
            model,
            str(max_tokens),
            str(temperature),
        ],
        cwd=str(lilo_root),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "LILO AutoDoc eval bridge failed")
    return _read_json(output_path)


def _fixture_response(fixture, condition_name, task, inventory, sample_index):
    explicit = (
        fixture.get("responses", {})
        .get(condition_name, {})
        .get(task["id"])
    )
    if explicit:
        item = explicit[sample_index % len(explicit)] if isinstance(explicit, list) else explicit
        if isinstance(item, str):
            return {"source": "fixture", "text": item}
        return {"source": "fixture", "text": json.dumps(item), "data": item}

    data = _correct_response_for_task(task)
    if condition_name == "raw_names":
        data = _degraded_response_for_task(task, inventory)
    elif condition_name == "typed_names" and task["type"] == "helper_selection":
        data = _correct_response_for_task(task)
    elif condition_name == "autodoc_names" and task["type"] == "raw_codeql_rejection":
        data = _correct_response_for_task(task)
    return {"source": "fixture", "text": json.dumps(data, indent=2), "data": data}


def _correct_response_for_task(task):
    if task["type"] == "role_classification":
        return {"roles": task.get("expected_roles", {})}
    if task["type"] == "grouping":
        return {"groups": task.get("expected_groups", {})}
    if task["type"] == "rewrite_reference":
        return {
            "proposals": [
                {"schema": "rewrite_candidate_reference_v1", "candidate_ref": ref}
                for ref in task.get("expected", [])
            ]
        }
    return {"selected": task.get("expected", []), "no_raw_codeql": True}


def _degraded_response_for_task(task, inventory):
    valid_ids = [item["id"] for item in inventory]
    if task["type"] == "role_classification":
        return {"roles": {candidate_id: "Other" for candidate_id in task.get("expected_roles", {})}}
    if task["type"] == "grouping":
        return {"groups": {"sources": valid_ids, "sinks": [], "barriers": []}}
    wrong = _wrong_ref(valid_ids, set(task.get("expected", [])))
    if task["type"] == "rewrite_reference":
        return {
            "proposals": [
                {
                    "schema": "rewrite_candidate_reference_v1",
                    "candidate_ref": wrong,
                    "body": "predicate bad(DataFlow::Node n) { any() }",
                }
            ]
        }
    return {
        "selected": [wrong],
        "body": "predicate bad(DataFlow::Node n) { any() }",
    }


def _wrong_ref(valid_ids, expected):
    for candidate_id in valid_ids:
        if candidate_id not in expected:
            return candidate_id
    return valid_ids[0] if valid_ids else "candidate:unknown"


def _extract_json(text):
    text = text.strip()
    if not text:
        raise ValueError("empty response")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        return json.loads(fenced.group(1))
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("no JSON object found")
    return json.loads(text[start : end + 1])


def _selected_refs(data, alias_map=None):
    if not isinstance(data, dict):
        return set()
    alias_map = alias_map or {}
    refs = set()
    for key in ["selected", "candidate_refs", "target_ids"]:
        refs.update(_candidate_refs_from_value(data.get(key), alias_map))
    for key in ["candidate_ref", "target_id"]:
        value = data.get(key)
        refs.update(_candidate_refs_from_value(value, alias_map))
    for proposal in data.get("proposals", []) if isinstance(data.get("proposals"), list) else []:
        if isinstance(proposal, dict):
            refs.update(_candidate_refs_from_value(proposal.get("candidate_ref"), alias_map))
            refs.update(_candidate_refs_from_value(proposal.get("target_id"), alias_map))
    return refs


def _all_candidate_refs(data, alias_map=None):
    alias_map = alias_map or {}
    refs = set()
    for value in _walk_values(data):
        refs.update(_candidate_refs_from_value(value, alias_map))
    return refs


def _candidate_refs_from_value(value, alias_map=None):
    alias_map = alias_map or {}
    if isinstance(value, str):
        if value.startswith("candidate:"):
            return {value}
        canonical = alias_map.get(value)
        return {canonical} if canonical else set()
    if isinstance(value, list):
        refs = set()
        for item in value:
            refs.update(_candidate_refs_from_value(item, alias_map))
        return refs
    return set()


def _walk_values(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_values(item)
    else:
        yield value


def _observed_groups(data, alias_map=None):
    alias_map = alias_map or {}
    groups = data.get("groups", {}) if isinstance(data, dict) else {}
    if isinstance(groups, dict):
        return {
            "sources": sorted(_candidate_refs_from_value(groups.get("sources", []), alias_map)),
            "sinks": sorted(_candidate_refs_from_value(groups.get("sinks", []), alias_map)),
            "barriers": sorted(_candidate_refs_from_value(groups.get("barriers", []), alias_map)),
        }
    return {"sources": [], "sinks": [], "barriers": []}


def _candidate_aliases(inventory):
    aliases = {}
    for item in inventory:
        canonical = item["id"]
        for key in ["id", "name", "raw_name", "autodoc_name"]:
            value = item.get(key)
            if value:
                aliases[value] = canonical
        if item.get("id", "").startswith("candidate:"):
            aliases[item["id"].replace("candidate:", "")] = canonical
    return aliases


def _looks_like_role_map(data, alias_map):
    if not isinstance(data, dict) or not data:
        return False
    role_values = {"Source", "Sink", "Barrier", "FlowStep", "Other"}
    for key, value in data.items():
        if key not in alias_map and not str(key).startswith("candidate:"):
            return False
        if _normalize_role(value) not in role_values:
            return False
    return True


def _canonical_role_map(roles, alias_map):
    if not isinstance(roles, dict):
        return {}
    canonical = {}
    for key, value in roles.items():
        candidate_id = key if str(key).startswith("candidate:") else alias_map.get(key)
        if candidate_id:
            canonical[candidate_id] = value
    return canonical


def _contains_raw_codeql(text, data):
    patterns = [
        r"\bpredicate\s+\w+\s*\(",
        r"\bimport\s+java\b",
        r"\bselect\s+",
        r"DataFlow::",
        r"TaintTracking::",
        r"\.ql\b",
    ]
    haystack = text
    if data is not None:
        haystack += "\n" + json.dumps(data)
    return any(re.search(pattern, haystack) for pattern in patterns)


def _expected_groups(inventory):
    groups = {"sources": [], "sinks": [], "barriers": []}
    for item in inventory:
        if item["group"] in groups:
            groups[item["group"]].append(item["id"])
    return {key: sorted(value) for key, value in groups.items()}


def _group_for_role(role):
    role = _normalize_role(role)
    if role == "Source":
        return "sources"
    if role == "Sink":
        return "sinks"
    if role == "Barrier":
        return "barriers"
    return "other"


def _role_from_schema(schema):
    if "source" in schema:
        return "Source"
    if "sink" in schema:
        return "Sink"
    if "barrier" in schema or "sanitizer" in schema:
        return "Barrier"
    return "Other"


def _normalize_role(role):
    text = str(role or "").strip().lower()
    aliases = {
        "source": "Source",
        "sink": "Sink",
        "barrier": "Barrier",
        "sanitizer": "Barrier",
        "flowstep": "FlowStep",
        "flow_step": "FlowStep",
        "additionalflowstep": "FlowStep",
        "additional_flow_step": "FlowStep",
        "sourcekind": "Source",
        "source_kind": "Source",
        "threatmodel": "Source",
        "threat_model": "Source",
        "sinkkind": "Sink",
        "sink_kind": "Sink",
        "modeledsinktype": "Sink",
        "modeled_sink_type": "Sink",
        "methodcallsink": "Sink",
        "method_call_sink": "Sink",
        "barrierkind": "Barrier",
        "barrier_kind": "Barrier",
        "helperpredicate": "Other",
        "helper_predicate": "Other",
        "other": "Other",
    }
    return aliases.get(text.replace(" ", "_"), aliases.get(text, "Other"))


def _set_f1(expected, observed):
    if not expected and not observed:
        return 1.0
    if not expected or not observed:
        return 0.0
    tp = len(expected & observed)
    precision = tp / len(observed) if observed else 0.0
    recall = tp / len(expected) if expected else 0.0
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def _rate(values):
    values = list(values)
    if not values:
        return None
    return sum(1 for value in values if value) / len(values)


def _mean(values):
    values = [value for value in values if value is not None]
    if not values:
        return None
    return sum(values) / len(values)


def _primary_comparison(scores):
    raw = scores.get("raw_names", {}).get("aggregate_score")
    docs = scores.get("autodoc_docstrings", {}).get("aggregate_score")
    if raw is None or docs is None:
        return None
    return {
        "baseline": "raw_names",
        "treatment": "autodoc_docstrings",
        "baseline_aggregate_score": raw,
        "treatment_aggregate_score": docs,
        "delta": docs - raw,
        "improved": docs > raw,
    }


def _write_report(summary, inventory, tasks):
    lines = [
        "# CyberSTITCH AutoDoc Evaluation",
        "",
        "Status: completed",
        "Mode: `{}`".format(summary["mode"]),
        "Model: `{}`".format(summary["model"]),
        "Source results: `{}`".format(summary["source_results"]),
        "Inventory items: `{}`".format(len(inventory)),
        "Tasks: `{}`".format(len(tasks)),
        "Samples per task: `{}`".format(summary["samples"]),
        "",
        "## Scores",
        "",
    ]
    for condition, scores in summary["scores"].items():
        lines.append(
            "- `{}` aggregate=`{}` success=`{}` parse=`{}` raw_codeql_violations=`{}`".format(
                condition,
                _fmt(scores.get("aggregate_score")),
                _fmt(scores.get("task_success_rate")),
                _fmt(scores.get("parse_rate")),
                _fmt(scores.get("raw_codeql_violation_rate")),
            )
        )
    comparison = summary.get("primary_comparison") or {}
    if comparison:
        lines.extend(
            [
                "",
                "## Primary Comparison",
                "",
                "- baseline: `{}`".format(comparison["baseline"]),
                "- treatment: `{}`".format(comparison["treatment"]),
                "- delta: `{}`".format(_fmt(comparison["delta"])),
                "- improved: `{}`".format(comparison["improved"]),
            ]
        )
    lines.extend(
        [
            "",
            "## Policy",
            "",
            "This evaluation measures LLM usability of validated abstractions. It does not change CodeQL query semantics or vulnerability-detection scores.",
        ]
    )
    return "\n".join(lines) + "\n"


def _fmt(value):
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return "{:.3f}".format(value)
    return str(value)


def _resolve_source_results(config, source_results):
    if source_results:
        return Path(source_results).resolve()
    if (config.results_dir / "validation" / "decisions.json").exists():
        return config.results_dir.resolve()
    fallback = config.root / "results" / DEFAULT_SOURCE_RESULTS
    if fallback.exists():
        return fallback.resolve()
    return config.results_dir.resolve()


def _default_lilo_python():
    return Path(__file__).resolve().parents[2] / "lilo_sec" / ".conda" / "envs" / "lilo" / "bin" / "python"


def _default_cache_dir(config):
    override = os.environ.get("LILO_LLM_CACHE_DIR")
    if override:
        return Path(override)
    return config.root.parent / "Info" / "llm_caches" / "cyberstitch_autodoc_gpt35_20260507"


def _load_autodoc(path):
    docs = {}
    data = _read_json(path)
    if isinstance(data, list):
        for item in data:
            target = item.get("target_id") or item.get("candidate_ref")
            if target:
                docs[target] = item
                docs[target.replace("candidate:", "")] = item
    return docs


def _load_fixture(path):
    if not path:
        return {}
    path = Path(path)
    if not path.exists():
        raise RuntimeError("AutoDoc eval fixture not found: {}".format(path))
    data = json.loads(path.read_text())
    if data.get("format") != AUTODOC_EVAL_FIXTURE_FORMAT:
        raise RuntimeError("unsupported AutoDoc eval fixture format: {}".format(data.get("format")))
    return data


def _read_json(path):
    path = Path(path)
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def _write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
