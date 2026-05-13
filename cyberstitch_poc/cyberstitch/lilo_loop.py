import json
import os
from datetime import datetime, timezone
from pathlib import Path


LILO_LOOP_INPUT_FORMAT = "cyberstitch-lilo-loop-input-v1"
LILO_LOOP_OUTPUT_FORMAT = "cyberstitch-lilo-loop-output-v1"
LILO_LOOP_PARTITIONS_FORMAT = "cyberstitch-lilo-loop-partitions-v1"
DEFAULT_PROMPT_BYTE_BUDGET = 45000
DEFAULT_MAX_USE_SITE_EXAMPLES = 2

ROLE_FAMILY_ORDER = ["sources", "sinks", "barriers", "flow_helpers", "misc"]
ROLE_FAMILY_LABELS = {
    "sources": "Sources",
    "sinks": "Sinks",
    "barriers": "Barriers",
    "flow_helpers": "Flow and helpers",
    "misc": "Miscellaneous",
}


def export_lilo_loop_input(config, output_path=None):
    """Export CyberSTITCH semantic state as LILO loop library items."""
    results_dir = Path(config.results_dir)
    output_path = Path(output_path or results_dir / "lilo-loop" / "input.json")
    provenance_paths = [
        results_dir / "fcir" / "provenance.json",
        results_dir / "fcir" / "codeql-pack" / "provenance.json",
    ]
    candidate_paths = [
        results_dir / "stitch" / "candidates.json",
        results_dir / "semantic" / "candidates.json",
    ]
    decisions_path = results_dir / "validation" / "decisions.json"

    provenance = _merge_provenance(path for path in provenance_paths if path.exists())
    decisions = _load_decisions(decisions_path)
    candidates = _load_candidates(candidate_paths)
    library_items = _library_items(candidates, decisions)
    concepts = _concept_items(provenance)
    scores = _load_scores(results_dir / "score")
    comparisons = _load_comparisons(results_dir / "compare")

    data = {
        "format": LILO_LOOP_INPUT_FORMAT,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "domain": "codeql-java-security",
        "backend": "cyberstitch-codeql",
        "strategy": {
            "lilo_role": "LLM search, grouping, naming, and autodoc over semantic abstraction objects.",
            "cyberstitch_role": "SQIR/FCIR semantics, deterministic CodeQL rewrites, syntax checks, and SARIF equivalence gates.",
            "raw_codeql_policy": "LLM-authored raw CodeQL is not executable in this milestone.",
        },
        "source_files": {
            "provenance": [str(path) for path in provenance_paths if path.exists()],
            "candidates": [str(path) for path in candidate_paths if path.exists()],
            "decisions": str(decisions_path) if decisions_path.exists() else None,
        },
        "summary": {
            "programs": len(provenance.get("programs", [])),
            "semantic_nodes": sum(len(program.get("semantic_nodes", [])) for program in provenance.get("programs", [])),
            "concepts": len(concepts),
            "library_items": len(library_items),
            "rewrite_eligible_items": sum(1 for item in library_items if item.get("rewrite_eligible")),
            "accepted_items": sum(1 for item in library_items if item.get("validation", {}).get("accepted") is True),
            "accepted_for_lilo_items": sum(
                1 for item in library_items
                if item.get("validation", {}).get("accepted_for_lilo") is True
            ),
            "rejected_items": sum(1 for item in library_items if item.get("validation", {}).get("accepted") is False),
        },
        "scores": scores,
        "comparisons": comparisons,
        "library_items": library_items,
        "concepts": concepts,
        "validation_gates": [
            "cyberstitch candidate schema validation",
            "SQIR/FCIR semantic validation",
            "deterministic CodeQL rewrite",
            "CodeQL syntax check",
            "SARIF equivalence against baseline unless explicitly marked as a delta experiment",
        ],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2))
    return data


def write_lilo_loop_sidecars(loop_result, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    sidecars = {}
    for key, filename in [
        ("autodoc", "autodoc.json"),
        ("groupings", "groupings.json"),
        ("query_synthesis_hints", "query-synthesis-hints.json"),
        ("ignored_outputs", "ignored.json"),
    ]:
        path = output_dir / filename
        path.write_text(json.dumps(loop_result.get(key, []), indent=2))
        sidecars[key] = str(path)

    summary = {
        "format": LILO_LOOP_OUTPUT_FORMAT,
        "source": loop_result.get("source"),
        "proposals": loop_result.get("proposals", 0),
        "candidates": loop_result.get("candidates", 0),
        "autodoc": len(loop_result.get("autodoc", [])),
        "groupings": len(loop_result.get("groupings", [])),
        "query_synthesis_hints": len(loop_result.get("query_synthesis_hints", [])),
        "ignored_outputs": len(loop_result.get("ignored_outputs", [])),
        "candidates_file": loop_result.get("output"),
        "sidecars": sidecars,
    }
    for key in [
        "partitions_file",
        "partition_mode",
        "partition_count",
        "prompt_byte_budget",
        "prompt_bytes",
        "selected_item_count",
        "selected_concept_count",
        "model",
        "cache_mode",
    ]:
        if key in loop_result:
            summary[key] = loop_result.get(key)
    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    report_path = output_dir / "report.md"
    report_path.write_text(_loop_report(summary, loop_result))
    summary["summary_file"] = str(summary_path)
    summary["report"] = str(report_path)
    return summary


def run_lilo_loop(
    provenance_path,
    output_dir,
    input_path,
    mode="fixture",
    fixture_path=None,
    lilo_python=None,
    model=None,
    max_tokens=1600,
    partition_mode="auto",
    prompt_byte_budget=DEFAULT_PROMPT_BYTE_BUDGET,
    max_library_items=None,
    max_concepts_per_partition=None,
    max_use_site_examples=DEFAULT_MAX_USE_SITE_EXAMPLES,
):
    """Run fixture or live LILO loop calls over prepared prompt partitions."""
    from .llm import run_llm_propose
    from .semantic import merge_candidate_files

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    input_path = Path(input_path)
    lilo_input = _read_json(input_path)
    if not lilo_input:
        raise RuntimeError("LILO loop input is empty or missing: {}".format(input_path))

    manifest = prepare_lilo_loop_partitions(
        lilo_input,
        output_dir,
        partition_mode=partition_mode,
        prompt_byte_budget=prompt_byte_budget,
        max_library_items=max_library_items,
        max_concepts_per_partition=max_concepts_per_partition,
        max_use_site_examples=max_use_site_examples,
        model=model,
    )

    partition_results = []
    for partition in manifest["partitions"]:
        partition_input_path = Path(partition["input"])
        partition_output_path = Path(partition["output"])
        partition_input = _read_json(partition_input_path)
        allowed_refs = _allowed_partition_references(partition_input)
        result = run_llm_propose(
            provenance_path=provenance_path,
            output_path=partition_output_path,
            lilo_python=lilo_python,
            fixture_path=fixture_path if mode == "fixture" else None,
            model=model,
            max_tokens=max_tokens,
            lilo_input_path=partition_input_path,
            allowed_lilo_ids=allowed_refs,
            partition_id=partition["id"],
        )
        raw_path = Path(partition["raw_response"])
        if not raw_path.exists():
            raw_path.write_text(json.dumps(_read_json(partition_output_path).get("raw_output", {}), indent=2))
        summary = {
            "id": partition["id"],
            "role_family": partition["role_family"],
            "prompt_bytes": partition["prompt_bytes"],
            "library_items": partition["library_item_count"],
            "concepts": partition["concept_count"],
            "proposals": result.get("proposals", 0),
            "candidates": result.get("candidates", 0),
            "autodoc": len(result.get("autodoc", [])),
            "groupings": len(result.get("groupings", [])),
            "query_synthesis_hints": len(result.get("query_synthesis_hints", [])),
            "ignored_outputs": len(result.get("ignored_outputs", [])),
            "input": str(partition_input_path),
            "prompt": partition["prompt"],
            "raw_response": str(raw_path),
            "output": str(partition_output_path),
        }
        Path(partition["summary"]).write_text(json.dumps(summary, indent=2))
        partition.update(
            {
                "result_summary": str(partition["summary"]),
                "proposals": result.get("proposals", 0),
                "candidates": result.get("candidates", 0),
                "autodoc": len(result.get("autodoc", [])),
                "groupings": len(result.get("groupings", [])),
                "query_synthesis_hints": len(result.get("query_synthesis_hints", [])),
                "ignored_outputs": len(result.get("ignored_outputs", [])),
            }
        )
        partition_results.append(result)

    partitions_path = output_dir / "partitions.json"
    partitions_path.write_text(json.dumps(manifest, indent=2))

    output_path = output_dir / "candidates.json"
    merged_candidates = merge_candidate_files(
        [result["output"] for result in partition_results],
        output_path,
    )
    result_source = "lilo-loop-partitioned"
    if len(partition_results) == 1:
        result_source = partition_results[0].get("source", result_source)
        merged_candidates["source"] = result_source
        output_path.write_text(json.dumps(merged_candidates, indent=2))
    merged = _merge_partition_sidecars(partition_results)
    merged.update(
        {
            "format": "cyberstitch-candidates-v2",
            "source": result_source,
            "output": str(output_path),
            "proposals": sum(result.get("proposals", 0) for result in partition_results),
            "candidates": len(merged_candidates.get("candidates", [])),
            "candidate_summaries": [
                {
                    "name": candidate.get("name", ""),
                    "schema": candidate.get("schema", ""),
                    "rewrite_eligible": candidate.get("rewrite_eligible", False),
                }
                for candidate in merged_candidates.get("candidates", [])
            ],
            "partitions_file": str(partitions_path),
            "partition_mode": manifest["partition_mode"],
            "partition_count": len(manifest["partitions"]),
            "prompt_byte_budget": manifest["prompt_byte_budget"],
            "prompt_bytes": [partition["prompt_bytes"] for partition in manifest["partitions"]],
            "selected_item_count": manifest["selected_item_count"],
            "selected_concept_count": manifest["selected_concept_count"],
            "model": manifest.get("model"),
            "cache_mode": manifest.get("cache_mode"),
        }
    )
    sidecar_summary = write_lilo_loop_sidecars(merged, output_dir)
    merged["lilo_loop_summary"] = sidecar_summary
    return merged


def prepare_lilo_loop_partitions(
    lilo_input,
    output_dir,
    partition_mode="auto",
    prompt_byte_budget=DEFAULT_PROMPT_BYTE_BUDGET,
    max_library_items=None,
    max_concepts_per_partition=None,
    max_use_site_examples=DEFAULT_MAX_USE_SITE_EXAMPLES,
    model=None,
):
    partition_mode = partition_mode or "auto"
    if partition_mode not in {"auto", "off", "role"}:
        raise ValueError("partition_mode must be one of: auto, off, role")
    prompt_byte_budget = int(prompt_byte_budget or DEFAULT_PROMPT_BYTE_BUDGET)
    max_library_items = _positive_int_or_none(max_library_items)
    max_concepts_per_partition = _positive_int_or_none(max_concepts_per_partition)
    max_use_site_examples = int(max_use_site_examples or DEFAULT_MAX_USE_SITE_EXAMPLES)
    output_dir = Path(output_dir)
    partitions_root = output_dir / "partitions"
    partitions_root.mkdir(parents=True, exist_ok=True)

    selected_items = select_lilo_prompt_inventory(lilo_input, max_library_items=max_library_items)
    selected_item_ids = {item.get("id", "") for item in selected_items}
    all_concepts = _dedupe_by_id(lilo_input.get("concepts", []))
    selected_concepts = _concepts_for_items(all_concepts, selected_items)
    full_prompt_concepts = _limit_concepts(selected_concepts, max_concepts_per_partition)

    full_prompt_input = _partition_lilo_input(
        lilo_input,
        "all",
        "all",
        selected_items,
        full_prompt_concepts,
        max_use_site_examples=max_use_site_examples,
    )
    full_prompt = render_lilo_loop_prompt(full_prompt_input)
    full_prompt_bytes = _byte_len(full_prompt)

    if partition_mode == "off" or (
        partition_mode == "auto" and full_prompt_bytes <= prompt_byte_budget
    ):
        specs = [("all", "all", selected_items, full_prompt_concepts)]
    else:
        specs = []
        by_family = {family: [] for family in ROLE_FAMILY_ORDER}
        for item in selected_items:
            by_family[_role_family(item)].append(item)
        concepts_by_family = {family: [] for family in ROLE_FAMILY_ORDER}
        for concept in selected_concepts:
            concepts_by_family[_role_family(concept)].append(concept)
        for family in ROLE_FAMILY_ORDER:
            items = by_family[family]
            concepts = _limit_concepts(concepts_by_family[family], max_concepts_per_partition)
            if not items and not concepts:
                continue
            specs.extend(
                _chunk_partition_specs(
                    lilo_input,
                    family,
                    items,
                    concepts,
                    prompt_byte_budget,
                    max_use_site_examples,
                )
            )
        if not specs:
            specs = [("all", "all", [], [])]

    partitions = []
    for partition_id, role_family, items, concepts in specs:
        prompt_input = _partition_lilo_input(
            lilo_input,
            partition_id,
            role_family,
            items,
            concepts,
            max_use_site_examples=max_use_site_examples,
        )
        prompt = render_lilo_loop_prompt(prompt_input)
        partition_dir = partitions_root / partition_id
        partition_dir.mkdir(parents=True, exist_ok=True)
        input_path = partition_dir / "input.json"
        prompt_path = partition_dir / "llm-prompt.txt"
        raw_path = partition_dir / "llm-raw-response.json"
        output_path = partition_dir / "candidates.json"
        summary_path = partition_dir / "summary.json"
        input_path.write_text(json.dumps(prompt_input, indent=2))
        prompt_path.write_text(prompt)
        partitions.append(
            {
                "id": partition_id,
                "role_family": role_family,
                "role_family_label": ROLE_FAMILY_LABELS.get(role_family, role_family),
                "library_item_count": len(items),
                "concept_count": len(concepts),
                "library_item_ids": [item.get("id", "") for item in items],
                "concept_ids": [item.get("id", "") for item in concepts],
                "prompt_bytes": _byte_len(prompt),
                "input": str(input_path),
                "prompt": str(prompt_path),
                "raw_response": str(raw_path),
                "output": str(output_path),
                "summary": str(summary_path),
            }
        )

    selected_concept_ids = sorted(
        {
            concept.get("id", "")
            for _, _, _, concepts in specs
            for concept in concepts
            if concept.get("id")
        }
    )
    manifest = {
        "format": LILO_LOOP_PARTITIONS_FORMAT,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "partition_mode": partition_mode,
        "prompt_byte_budget": prompt_byte_budget,
        "single_prompt_bytes": full_prompt_bytes,
        "selected_item_count": len(selected_items),
        "selected_concept_count": len(selected_concept_ids),
        "selected_item_ids": sorted(selected_item_ids),
        "selected_concept_ids": selected_concept_ids,
        "partition_count": len(partitions),
        "model": model or os.environ.get("CYBERSTITCH_LLM_MODEL") or "gpt-3.5-turbo",
        "cache_mode": os.environ.get("LILO_LLM_CACHE_MODE") or os.environ.get("CYBERSTITCH_LLM_CACHE_MODE"),
        "partitions": partitions,
    }
    (output_dir / "partitions.json").write_text(json.dumps(manifest, indent=2))
    return manifest


def select_lilo_prompt_inventory(lilo_input, max_library_items=None):
    items = list(lilo_input.get("library_items", []))
    max_library_items = _positive_int_or_none(max_library_items)
    has_validation_decisions = any(_has_validation_decision(item) for item in items)

    selected = []
    selected_keys = set()

    def add(item):
        key = item.get("id") or item.get("name") or item.get("semantic_hash")
        if key in selected_keys:
            return False
        selected_keys.add(key)
        selected.append(item)
        return True

    if has_validation_decisions:
        rewrite_accepted = [
            item for item in items
            if item.get("rewrite_eligible")
            and item.get("kind") == "codeql_helper"
            and item.get("validation", {}).get("accepted") is True
        ]
        for item in sorted(rewrite_accepted, key=_inventory_rank):
            add(item)

        accepted_for_lilo = [
            item for item in items
            if item.get("validation", {}).get("accepted_for_lilo") is True
        ]
        for item in sorted(accepted_for_lilo, key=_inventory_rank):
            if max_library_items and len(selected) >= max_library_items:
                break
            add(item)
    else:
        for item in sorted(items, key=_inventory_rank):
            if max_library_items and len(selected) >= max_library_items:
                break
            add(item)

    return selected


def render_lilo_loop_prompt(lilo_input):
    prompt_options = lilo_input.get("prompt_options", {})
    max_use_site_examples = int(
        prompt_options.get("max_use_site_examples") or DEFAULT_MAX_USE_SITE_EXAMPLES
    )
    library_items = [
        _prompt_library_item(item, max_use_site_examples=max_use_site_examples)
        for item in lilo_input.get("library_items", [])
    ]
    concepts = [_prompt_concept(item) for item in lilo_input.get("concepts", [])]
    example_candidate_id = library_items[0]["id"] if library_items else "candidate:example"
    example_concept_id = concepts[0]["id"] if concepts else "concept:example"
    instruction = {
        "task": "Run the LILO loop over CyberSTITCH CodeQL semantic abstraction objects.",
        "goal": (
            "Propose names, documentation, groupings, and provenance-backed rewrite "
            "references that preserve CodeQL semantics. Do not write executable CodeQL."
        ),
        "constraints": [
            "Return one JSON object only.",
            "Do not return Markdown, headings, prose, bullet lists, or fenced code blocks.",
            "The JSON object must contain a top-level proposals array.",
            "Every proposal must use one of the allowed schemas.",
            "Use only target_id, target_ids, candidate_ref, or concept ids present in this prompt.",
            "Do not reference candidates or concepts from outside this prompt partition.",
            "Do not write executable CodeQL, QL predicate bodies, imports, select clauses, or source code.",
        ],
        "domain": lilo_input.get("domain", "codeql-java-security"),
        "partition": lilo_input.get("partition", {}),
        "summary": lilo_input.get("summary", {}),
        "validation_policy": lilo_input.get("validation_gates", []),
        "raw_codeql_policy": "Raw QL, predicate bodies, or handwritten CodeQL snippets are advisory only and will be rejected for execution.",
        "allowed_schemas": [
            "autodoc_v1",
            "candidate_grouping_v1",
            "rewrite_candidate_reference_v1",
            "query_synthesis_hint_v1",
            "java_source_predicate_helper_v1",
            "java_sink_predicate_helper_v1",
        ],
        "response_format": {
            "proposals": [
                {
                    "schema": "autodoc_v1",
                    "target_id": example_candidate_id,
                    "display_name": "remote_flow_source",
                    "description": "one sentence",
                    "rationale": "why this is semantically reusable",
                },
                {
                    "schema": "rewrite_candidate_reference_v1",
                    "candidate_ref": example_candidate_id,
                    "display_name": "remote_flow_source",
                    "description": "one sentence",
                    "rationale": "why this existing candidate should stay rewrite-enabled",
                },
                {
                    "schema": "query_synthesis_hint_v1",
                    "target_ids": [example_concept_id],
                    "hint": "future query-synthesis guidance; not executable in this milestone",
                },
            ]
        },
        "library_items": library_items,
        "semantic_concepts": concepts,
    }
    return json.dumps(instruction, indent=2)


def _merge_partition_sidecars(partition_results):
    return {
        "autodoc": _dedupe_sidecars(
            item for result in partition_results for item in result.get("autodoc", [])
        ),
        "groupings": _dedupe_sidecars(
            item for result in partition_results for item in result.get("groupings", [])
        ),
        "query_synthesis_hints": _dedupe_sidecars(
            item for result in partition_results for item in result.get("query_synthesis_hints", [])
        ),
        "ignored_outputs": _dedupe_ignored(
            item for result in partition_results for item in result.get("ignored_outputs", [])
        ),
    }


def _dedupe_sidecars(items):
    deduped = []
    seen = set()
    for item in items:
        key = (item.get("schema", ""), tuple(_proposal_reference_ids(item)))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _dedupe_ignored(items):
    deduped = []
    seen = set()
    for item in items:
        key = (
            item.get("schema", ""),
            item.get("reason", ""),
            tuple(item.get("references", [])),
            item.get("partition_id", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _chunk_partition_specs(
    lilo_input,
    family,
    items,
    concepts,
    prompt_byte_budget,
    max_use_site_examples,
):
    if not items:
        return [(family, family, [], concepts)]

    chunks = []
    current = []
    for item in items:
        candidate = current + [item]
        partition_id = _chunk_partition_id(family, len(chunks) + 1, multiple=True)
        prompt_input = _partition_lilo_input(
            lilo_input,
            partition_id,
            family,
            candidate,
            concepts,
            max_use_site_examples=max_use_site_examples,
        )
        if current and _byte_len(render_lilo_loop_prompt(prompt_input)) > prompt_byte_budget:
            chunks.append(current)
            current = [item]
        else:
            current = candidate
    if current:
        chunks.append(current)

    if len(chunks) == 1:
        return [(family, family, chunks[0], concepts)]
    return [
        (_chunk_partition_id(family, index + 1, multiple=True), family, chunk, concepts)
        for index, chunk in enumerate(chunks)
    ]


def _chunk_partition_id(family, index, multiple=False):
    if not multiple:
        return family
    return "{}-{:03d}".format(family, index)


def _partition_lilo_input(
    lilo_input,
    partition_id,
    role_family,
    library_items,
    concepts,
    max_use_site_examples=DEFAULT_MAX_USE_SITE_EXAMPLES,
):
    summary = dict(lilo_input.get("summary", {}))
    summary.update(
        {
            "library_items": len(library_items),
            "concepts": len(concepts),
            "rewrite_eligible_items": sum(1 for item in library_items if item.get("rewrite_eligible")),
            "accepted_items": sum(
                1 for item in library_items if item.get("validation", {}).get("accepted") is True
            ),
            "accepted_for_lilo_items": sum(
                1
                for item in library_items
                if item.get("validation", {}).get("accepted_for_lilo") is True
            ),
        }
    )
    return {
        "format": lilo_input.get("format", LILO_LOOP_INPUT_FORMAT),
        "created_at": lilo_input.get("created_at"),
        "domain": lilo_input.get("domain", "codeql-java-security"),
        "backend": lilo_input.get("backend", "cyberstitch-codeql"),
        "strategy": lilo_input.get("strategy", {}),
        "source_files": lilo_input.get("source_files", {}),
        "partition": {
            "id": partition_id,
            "role_family": role_family,
            "role_family_label": ROLE_FAMILY_LABELS.get(role_family, role_family),
        },
        "prompt_options": {
            "max_use_site_examples": max_use_site_examples,
            "compact_fields_only": True,
        },
        "summary": summary,
        "scores": lilo_input.get("scores", {}),
        "comparisons": lilo_input.get("comparisons", {}),
        "library_items": library_items,
        "concepts": concepts,
        "validation_gates": lilo_input.get("validation_gates", []),
    }


def _concepts_for_items(concepts, items):
    if not concepts:
        return []
    families = {_role_family(item) for item in items}
    if not families:
        families = set(ROLE_FAMILY_ORDER)
    selected = [concept for concept in concepts if _role_family(concept) in families]
    return sorted(selected, key=_concept_rank)


def _limit_concepts(concepts, max_concepts):
    concepts = sorted(_dedupe_by_id(concepts), key=_concept_rank)
    if max_concepts:
        return concepts[:max_concepts]
    return concepts


def _dedupe_by_id(items):
    deduped = []
    seen = set()
    for item in items:
        key = item.get("id") or json.dumps(item, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _allowed_partition_references(lilo_input):
    refs = set()
    for item in lilo_input.get("library_items", []):
        candidate = item.get("candidate", {})
        for value in [
            item.get("id"),
            item.get("name"),
            item.get("semantic_hash"),
            candidate.get("name"),
            candidate.get("semantic_hash"),
        ]:
            if value:
                refs.add(value)
    for item in lilo_input.get("concepts", []):
        for value in [item.get("id"), item.get("name"), item.get("target")]:
            if value:
                refs.add(value)
    return refs


def _prompt_library_item(item, max_use_site_examples=DEFAULT_MAX_USE_SITE_EXAMPLES):
    use_sites = item.get("use_sites", [])
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
        "validation": _compact_validation(item.get("validation", {})),
        "description": item.get("description", ""),
        "use_site_count": len(use_sites),
        "use_site_examples": [
            _compact_use_site(use_site) for use_site in use_sites[:max_use_site_examples]
        ],
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


def _compact_validation(validation):
    if not validation:
        return {}
    compact = {}
    for key in ["accepted", "accepted_for_lilo"]:
        if key in validation:
            compact[key] = validation.get(key)
    reasons = validation.get("reasons") or []
    lilo_reasons = validation.get("lilo_reasons") or []
    if reasons:
        compact["reason_count"] = len(reasons)
        compact["reasons"] = reasons[:2]
    if lilo_reasons:
        compact["lilo_reason_count"] = len(lilo_reasons)
        compact["lilo_reasons"] = lilo_reasons[:2]
    return compact


def _compact_use_site(use_site):
    keep = [
        "query",
        "predicate",
        "semantic_node_id",
        "concept_kind",
        "target",
        "official_codeql",
    ]
    return {key: use_site[key] for key in keep if key in use_site}


def _has_validation_decision(item):
    validation = item.get("validation") or {}
    return "accepted" in validation or "accepted_for_lilo" in validation


def _inventory_rank(item):
    validation = item.get("validation") or {}
    semantic_validation = item.get("semantic_validation") or {}
    evidence = semantic_validation.get("evidence") or {}
    official = bool(evidence.get("official_codeql_backing")) or any(
        use_site.get("official_codeql") for use_site in item.get("use_sites", [])
    )
    return (
        0 if validation.get("accepted") is True else 1,
        0 if item.get("rewrite_eligible") and item.get("kind") == "codeql_helper" else 1,
        _role_priority(item),
        -len(item.get("use_sites", [])),
        0 if official else 1,
        item.get("name", ""),
        item.get("id", ""),
    )


def _concept_rank(item):
    return (
        _role_priority(item),
        0 if item.get("official_codeql") else 1,
        item.get("query", ""),
        item.get("target", ""),
        item.get("id", ""),
    )


def _role_priority(item):
    return {
        "Source": 0,
        "SourceKind": 0,
        "ThreatModel": 0,
        "Sink": 1,
        "ModeledSinkType": 1,
        "SinkKind": 1,
        "MethodCallSink": 1,
        "Barrier": 2,
        "BarrierKind": 2,
        "AdditionalFlowStep": 3,
        "FlowConfigTemplate": 3,
        "HelperPredicate": 3,
        "PathQueryShape": 3,
        "ProblemQueryShape": 3,
    }.get(_role_value(item), 9)


def _role_family(item):
    role = _role_value(item)
    schema = item.get("schema", "")
    name = item.get("name", "")
    text = " ".join([role, schema, name]).lower()
    if role in {"Source", "SourceKind", "ThreatModel"} or "source" in text:
        return "sources"
    if role in {"Sink", "SinkKind", "ModeledSinkType", "MethodCallSink"} or "sink" in text:
        return "sinks"
    if role in {"Barrier", "BarrierKind"} or "barrier" in text or "sanitizer" in text:
        return "barriers"
    if role in {
        "AdditionalFlowStep",
        "FlowConfigTemplate",
        "HelperPredicate",
        "PathQueryShape",
        "ProblemQueryShape",
    }:
        return "flow_helpers"
    return "misc"


def _role_value(item):
    return item.get("semantic_role") or item.get("concept_kind") or item.get("role") or ""


def _positive_int_or_none(value):
    if value is None:
        return None
    value = int(value)
    return value if value > 0 else None


def _byte_len(text):
    return len(text.encode("utf-8"))


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


def _merge_provenance(paths):
    merged = {
        "format": "cyberstitch-fcir-provenance",
        "version": "fcir-v2",
        "programs": [],
    }
    seen = set()
    for path in paths:
        data = _read_json(path)
        for program in data.get("programs", []):
            key = (
                program.get("program_id"),
                program.get("name"),
                program.get("sqir_hash") or program.get("provenance_hash"),
            )
            if key in seen:
                continue
            seen.add(key)
            merged["programs"].append(program)
    return merged


def _load_candidates(paths):
    candidates = []
    seen = set()
    for path in paths:
        data = _read_json(path)
        for candidate in data.get("candidates", []):
            key = (
                candidate.get("schema", ""),
                candidate.get("semantic_hash") or candidate.get("name", ""),
            )
            if key in seen:
                continue
            seen.add(key)
            compact = _compact_candidate(candidate)
            compact["_source_file"] = str(path)
            candidates.append(compact)
    return candidates


def _load_decisions(path):
    decisions = {}
    data = _read_json(path)
    for item in data.get("decisions", []):
        candidate = item.get("candidate", {})
        decision = {
            "accepted": item.get("accepted"),
            "reasons": item.get("reasons", []),
            "accepted_for_lilo": item.get("accepted_for_lilo"),
            "lilo_reasons": item.get("lilo_reasons", []),
        }
        for key in _candidate_keys(candidate):
            decisions[key] = decision
    return decisions


def _library_items(candidates, decisions):
    items = []
    for candidate in candidates:
        validation = {}
        for key in _candidate_keys(candidate):
            if key in decisions:
                validation = decisions[key]
                break
        item_id = _library_item_id(candidate)
        items.append(
            {
                "id": item_id,
                "type": "semantic_abstraction_candidate",
                "name": candidate.get("name", ""),
                "display_name": candidate.get("display_name") or candidate.get("name", ""),
                "kind": candidate.get("kind", ""),
                "origin": candidate.get("origin", ""),
                "schema": candidate.get("schema", ""),
                "language": candidate.get("language", ""),
                "semantic_hash": candidate.get("semantic_hash", ""),
                "semantic_role": candidate.get("semantic_role", ""),
                "semantic_target": candidate.get("semantic_target", ""),
                "semantic_usefulness": candidate.get("semantic_usefulness", ""),
                "rewrite_eligible": bool(candidate.get("rewrite_eligible")),
                "validation": validation,
                "description": candidate.get("description", ""),
                "predicate": candidate.get("predicate", ""),
                "helper_module": candidate.get("helper_module", ""),
                "use_sites": candidate.get("use_sites", []),
                "semantic_validation": candidate.get("semantic_validation", {}),
                "candidate": candidate,
            }
        )
    return items


def _concept_items(provenance):
    items = []
    for program in provenance.get("programs", []):
        for node in program.get("semantic_nodes", []):
            if node.get("kind") != "Concept":
                continue
            items.append(
                {
                    "id": "concept:{}".format(node.get("id", "")),
                    "type": "semantic_concept",
                    "program_id": program.get("program_id", ""),
                    "query": Path(program.get("name", "")).name,
                    "program_kind": program.get("kind", "SQIRQuery"),
                    "language": program.get("language", node.get("language", "")),
                    "cwe": node.get("cwe", program.get("cwe")),
                    "rule_id": node.get("rule_id", program.get("rule_id", "")),
                    "concept_kind": node.get("concept_kind", node.get("role", "")),
                    "semantic_role": node.get("semantic_role", ""),
                    "target": node.get("target", ""),
                    "name": node.get("name", ""),
                    "attributes": node.get("attributes", {}),
                    "official_codeql": program.get("kind") in {"CodeQLPackLibrary", "CodeQLPackQuery"},
                    "source_path": node.get("source", {}).get("path") or program.get("name", ""),
                }
            )
    return items


def _compact_candidate(candidate):
    keep = [
        "candidate_version",
        "name",
        "kind",
        "origin",
        "schema",
        "language",
        "helper_module",
        "predicate",
        "display_name",
        "description",
        "body",
        "use_sites",
        "rewrite_eligible",
        "semantic_hash",
        "semantic_role",
        "semantic_target",
        "semantic_usefulness",
        "semantic_validation",
        "mapping_status",
        "rationale",
    ]
    compact = {key: candidate[key] for key in keep if key in candidate}
    syntax = candidate.get("codeql_syntax_validation")
    if isinstance(syntax, dict):
        compact["codeql_syntax_validation"] = {"ok": syntax.get("ok", False)}
    return compact


def _candidate_keys(candidate):
    keys = []
    if candidate.get("name"):
        keys.append(("name", candidate["name"]))
    if candidate.get("semantic_hash"):
        keys.append(("semantic_hash", candidate["semantic_hash"]))
    if candidate.get("predicate"):
        keys.append(("predicate", candidate.get("helper_module", ""), candidate["predicate"]))
    return keys


def _library_item_id(candidate):
    if candidate.get("name"):
        return "candidate:{}".format(candidate["name"])
    if candidate.get("semantic_hash"):
        return "candidate:{}".format(candidate["semantic_hash"])
    return "candidate:unknown"


def _load_scores(score_dir):
    scores = {}
    for name in ["original", "roundtrip", "rewritten"]:
        data = _read_json(Path(score_dir) / "{}.json".format(name))
        if data:
            scores[name] = data.get("totals", data)
    return scores


def _load_comparisons(compare_dir):
    comparisons = {}
    for path in sorted(Path(compare_dir).glob("*.json")) if Path(compare_dir).exists() else []:
        data = _read_json(path)
        if data:
            comparisons[path.stem] = {
                "equivalent": data.get("equivalent"),
                "missing": len(data.get("missing", [])),
                "extra": len(data.get("extra", [])),
            }
    return comparisons


def _read_json(path):
    path = Path(path)
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def _loop_report(summary, loop_result):
    lines = [
        "# CyberSTITCH LILO Loop Report",
        "",
        "Source: `{}`".format(summary.get("source")),
        "Executable candidate proposals: `{}`".format(summary.get("candidates")),
        "Autodoc items: `{}`".format(summary.get("autodoc")),
        "Groupings: `{}`".format(summary.get("groupings")),
        "Query synthesis hints: `{}`".format(summary.get("query_synthesis_hints")),
        "Ignored outputs: `{}`".format(summary.get("ignored_outputs")),
        "",
        "## Policy",
        "",
        "LLM output is advisory. Only provenance-backed rewrite candidates are allowed to enter CyberSTITCH validation, rewrite, CodeQL syntax, and SARIF equivalence gates.",
        "",
        "## Candidate Proposals",
    ]
    for candidate in loop_result.get("candidate_summaries", []):
        lines.append(
            "- `{}` schema=`{}` rewrite_eligible=`{}`".format(
                candidate.get("name", ""),
                candidate.get("schema", ""),
                candidate.get("rewrite_eligible", False),
            )
        )
    if not loop_result.get("candidate_summaries"):
        lines.append("- none")
    lines.append("")
    lines.append("## Autodoc")
    for item in loop_result.get("autodoc", []):
        target = item.get("target_id") or item.get("candidate_ref") or item.get("semantic_hash", "")
        lines.append("- `{}`: {}".format(target, item.get("description", item.get("display_name", ""))))
    if not loop_result.get("autodoc"):
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)
