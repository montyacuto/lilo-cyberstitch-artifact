import json
import os
import subprocess
from pathlib import Path

from .abstractions import candidate_from_llm_proposal, invalid_llm_candidate, load_provenance
from .lilo_loop import render_lilo_loop_prompt


LILO_LLM_BRIDGE = r"""
import json
import sys

from src.openai_compat import create_completion, completion_to_dict

prompt_path, output_path, model, max_tokens = sys.argv[1:5]
prompt = open(prompt_path).read()
response = create_completion(
    model=model,
    prompt=None,
    messages=[{"role": "user", "content": prompt}],
    is_chat=True,
    temperature=0.0,
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


def run_llm_propose(
    provenance_path,
    output_path,
    lilo_python=None,
    lilo_root=None,
    fixture_path=None,
    model=None,
    max_tokens=1200,
    lilo_input_path=None,
    allowed_lilo_ids=None,
    partition_id=None,
):
    provenance = load_provenance(provenance_path)
    lilo_input = _load_json(lilo_input_path) if lilo_input_path else None
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if fixture_path:
        raw = json.loads(Path(fixture_path).read_text())
        source = "fixture"
    else:
        raw = _run_lilo_llm_bridge(
            provenance,
            output_path.parent,
            lilo_python=lilo_python,
            lilo_root=lilo_root,
            model=model,
            max_tokens=max_tokens,
            lilo_input=lilo_input,
        )
        source = "lilo-openai-compat"

    parsed = _extract_structured_outputs(
        raw,
        allowed_lilo_ids=allowed_lilo_ids,
        partition_id=partition_id,
    )
    candidates = []
    for proposal in parsed["proposals"]:
        if proposal.get("schema") == "rewrite_candidate_reference_v1":
            candidates.append(_candidate_from_lilo_reference(proposal, lilo_input))
        else:
            candidates.append(candidate_from_llm_proposal(proposal, provenance))
    result = {
        "format": "cyberstitch-candidates-v2",
        "source": source,
        "raw_output": raw,
        "lilo_input": str(lilo_input_path) if lilo_input_path else None,
        "autodoc": parsed["autodoc"],
        "groupings": parsed["groupings"],
        "query_synthesis_hints": parsed["query_synthesis_hints"],
        "ignored_outputs": parsed["ignored_outputs"],
        "candidates": candidates,
    }
    output_path.write_text(json.dumps(result, indent=2))
    return {
        "output": str(output_path),
        "source": source,
        "proposals": len(parsed["proposals"]),
        "candidates": len(candidates),
        "autodoc": parsed["autodoc"],
        "groupings": parsed["groupings"],
        "query_synthesis_hints": parsed["query_synthesis_hints"],
        "ignored_outputs": parsed["ignored_outputs"],
        "candidate_summaries": [
            {
                "name": candidate.get("name", ""),
                "schema": candidate.get("schema", ""),
                "rewrite_eligible": candidate.get("rewrite_eligible", False),
            }
            for candidate in candidates
        ],
    }


def _run_lilo_llm_bridge(
    provenance,
    work_dir,
    lilo_python=None,
    lilo_root=None,
    model=None,
    max_tokens=1200,
    lilo_input=None,
):
    lilo_python = Path(lilo_python or _default_lilo_python())
    lilo_root = Path(lilo_root or lilo_python.parents[4])
    if not lilo_python.exists():
        raise RuntimeError("LILO Python interpreter not found: {}".format(lilo_python))
    prompt_path = Path(work_dir) / "llm-prompt.txt"
    raw_path = Path(work_dir) / "llm-raw-response.json"
    prompt_path.write_text(_prompt_for_lilo_input(lilo_input) if lilo_input else _prompt_for_provenance(provenance))
    model = model or os.environ.get("CYBERSTITCH_LLM_MODEL") or "gpt-3.5-turbo"
    completed = subprocess.run(
        [
            str(lilo_python),
            "-c",
            LILO_LLM_BRIDGE,
            str(prompt_path),
            str(raw_path),
            model,
            str(max_tokens),
        ],
        cwd=str(lilo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "LILO LLM proposal bridge failed")
    return json.loads(raw_path.read_text())


def _extract_proposals(raw):
    return _extract_structured_outputs(raw)["proposals"]


def _extract_structured_outputs(raw, allowed_lilo_ids=None, partition_id=None):
    if "proposals" in raw:
        data = raw
    else:
        text = raw.get("text", "")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}")
            if start < 0 or end < start:
                raise RuntimeError("LLM response did not contain a JSON object")
            data = json.loads(text[start : end + 1])

    proposals = []
    autodoc = list(data.get("autodoc", []))
    groupings = list(data.get("groupings", []))
    hints = list(data.get("query_synthesis_hints", []))
    ignored = []
    allowed_lilo_ids = set(allowed_lilo_ids or [])
    for item in data.get("proposals", []):
        schema = item.get("schema", "")
        refs = _proposal_reference_ids(item)
        if allowed_lilo_ids:
            outside = [ref for ref in refs if ref not in allowed_lilo_ids]
            if outside:
                ignored.append(
                    _ignored_output(
                        schema,
                        "references outside prompt partition",
                        refs=outside,
                        partition_id=partition_id,
                    )
                )
                continue
        if schema == "autodoc_v1":
            autodoc.append(item)
        elif schema == "candidate_grouping_v1":
            groupings.append(item)
        elif schema == "query_synthesis_hint_v1":
            hints.append(item)
        else:
            proposals.append(item)
        if "codeql" in item or "body" in item:
            ignored.append(
                _ignored_output(
                    schema,
                    "raw CodeQL/body fields are advisory only and are not used for deterministic rewrites",
                    refs=refs,
                    partition_id=partition_id,
                )
            )
    return {
        "proposals": proposals,
        "autodoc": autodoc,
        "groupings": groupings,
        "query_synthesis_hints": hints,
        "ignored_outputs": ignored,
    }


def _proposal_reference_ids(item):
    refs = []
    for key in ["target_id", "candidate_ref", "semantic_hash"]:
        value = item.get(key)
        if value:
            refs.append(value)
    for key in ["target_ids", "semantic_node_ids"]:
        for value in item.get(key, []) or []:
            if value:
                refs.append(value)
    return sorted(set(refs))


def _ignored_output(schema, reason, refs=None, partition_id=None):
    ignored = {
        "schema": schema,
        "reason": reason,
    }
    if refs:
        ignored["references"] = sorted(set(refs))
    if partition_id:
        ignored["partition_id"] = partition_id
    return ignored


def _candidate_from_lilo_reference(proposal, lilo_input):
    if not lilo_input:
        return invalid_llm_candidate(proposal, "rewrite candidate reference requires a LILO loop input export")
    ref = proposal.get("candidate_ref") or proposal.get("target_id") or proposal.get("semantic_hash") or ""
    item = _find_library_item(lilo_input, ref)
    if not item:
        return invalid_llm_candidate(proposal, "unknown LILO library item reference")
    candidate = dict(item.get("candidate", {}))
    if candidate.get("kind") != "codeql_helper" or not candidate.get("rewrite_eligible"):
        return invalid_llm_candidate(proposal, "referenced item is not a rewrite-eligible CodeQL helper")
    if "predicate" not in candidate.get("body", ""):
        return invalid_llm_candidate(proposal, "referenced item does not contain deterministic CodeQL predicate body")
    candidate["origin"] = "lilo-loop"
    candidate["display_name"] = proposal.get("display_name") or candidate.get("display_name") or candidate.get("name", "")
    candidate["description"] = proposal.get("description") or candidate.get("description", "")
    candidate["rationale"] = proposal.get("rationale", "")
    candidate["llm_proposal"] = proposal
    validation = dict(candidate.get("semantic_validation") or {})
    evidence = dict(validation.get("evidence") or {})
    evidence["lilo_loop_reference"] = ref
    evidence["lilo_loop_policy"] = "referenced existing provenance-backed candidate; no raw CodeQL accepted"
    validation["evidence"] = evidence
    validation["ok"] = bool(validation.get("ok", True))
    validation.setdefault("reasons", [])
    candidate["semantic_validation"] = validation
    return candidate


def _find_library_item(lilo_input, ref):
    matches = []
    for item in lilo_input.get("library_items", []):
        candidate = item.get("candidate", {})
        values = {
            item.get("id", ""),
            item.get("name", ""),
            item.get("semantic_hash", ""),
            candidate.get("name", ""),
            candidate.get("semantic_hash", ""),
        }
        if ref in values:
            matches.append(item)
    if not matches:
        return None
    for item in matches:
        candidate = item.get("candidate", {})
        if candidate.get("kind") == "codeql_helper" and candidate.get("rewrite_eligible"):
            return item
    return matches[0]


def _prompt_for_provenance(provenance):
    nodes = []
    for program in provenance.get("programs", []):
        for node in program.get("semantic_nodes", []):
            if node.get("kind") != "Predicate":
                continue
            nodes.append(
                {
                    "semantic_node_id": node.get("id"),
                    "language": program.get("language"),
                    "query": Path(program.get("name", "")).name,
                    "role": node.get("role"),
                    "predicate": node.get("name"),
                    "target": node.get("target"),
                }
            )
    instruction = {
        "task": "Propose reusable CyberSTITCH CodeQL abstraction schemas. Do not write CodeQL.",
        "allowed_schemas": [
            "java_source_predicate_helper_v1",
            "java_sink_predicate_helper_v1",
            "java_remote_source_parameterized_sink_template_v1",
        ],
        "response_format": {
            "proposals": [
                {
                    "schema": "java_source_predicate_helper_v1",
                    "semantic_node_ids": ["q0:predicate:Config:isSource"],
                    "display_name": "short_snake_case_name",
                    "description": "one sentence",
                    "rationale": "why this is semantically reusable",
                }
            ]
        },
        "semantic_nodes": nodes,
    }
    return json.dumps(instruction, indent=2)


def _prompt_for_lilo_input(lilo_input):
    return render_lilo_loop_prompt(lilo_input)


def _prompt_library_item(item):
    return {
        "id": item.get("id", ""),
        "name": item.get("name", ""),
        "schema": item.get("schema", ""),
        "kind": item.get("kind", ""),
        "origin": item.get("origin", ""),
        "language": item.get("language", ""),
        "semantic_role": item.get("semantic_role", ""),
        "semantic_target": item.get("semantic_target", ""),
        "rewrite_eligible": item.get("rewrite_eligible", False),
        "validation": item.get("validation", {}),
        "description": item.get("description", ""),
        "use_sites": item.get("use_sites", [])[:8],
    }


def _prompt_concept(item):
    return {
        "id": item.get("id", ""),
        "query": item.get("query", ""),
        "cwe": item.get("cwe"),
        "concept_kind": item.get("concept_kind", ""),
        "semantic_role": item.get("semantic_role", ""),
        "target": item.get("target", ""),
        "official_codeql": item.get("official_codeql", False),
    }


def _load_json(path):
    path = Path(path)
    if not path.exists():
        return None
    return json.loads(path.read_text())


def _default_lilo_python():
    return Path(__file__).resolve().parents[2] / "lilo_sec" / ".conda" / "envs" / "lilo" / "bin" / "python"
