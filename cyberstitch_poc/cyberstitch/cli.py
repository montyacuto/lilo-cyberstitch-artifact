import argparse
import json
import os
import re
from pathlib import Path

from .autodoc_eval import run_autodoc_eval
from .codeql import (
    analyze_database,
    bundle_database,
    create_database,
    require_codeql,
    write_doctor,
)
from .codeql_pack import write_codeql_pack_corpus
from .config import load_config
from .discovery import discover_seed_queries
from .fcir import write_corpus
from .llm import run_llm_propose
from .lilo_loop import export_lilo_loop_input, run_lilo_loop
from .manifest import validate_manifest
from .parser import format_query, parse_query
from .report import write_report
from .rewrite import rewrite_queries
from .sarif import compare_sarif, score_sarif
from .seedgen import generate_seed_profile, validate_seed_manifest
from .semantic import merge_candidate_files, mine_semantic_candidates
from .stitch import run_stitch
from .syntax import run_codeql_check
from .validate import validate_candidates, validate_pipeline


def _query_paths(config):
    paths = sorted(config.query_dir.glob(config.query_glob))
    if config.language == "all":
        return paths
    return [path for path in paths if _file_language(path) == config.language]


def _relative_output(base_dir, query_dir, query_path, suffix=None):
    relative = query_path.relative_to(query_dir)
    if suffix:
        relative = relative.with_suffix(suffix)
    return base_dir / relative


def cmd_doctor(args):
    config = load_config(args.root)
    result = write_doctor(config, config.results_dir / "doctor.json")
    print(json.dumps(result, indent=2))


def cmd_sqir(args):
    config = load_config(args.root)
    out_dir = config.results_dir / "sqir"
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for path in _query_paths(config):
        query = parse_query(path)
        out_path = _relative_output(out_dir, config.query_dir, path, ".json")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(query.to_dict(), indent=2))
        written.append(str(out_path))
    print(json.dumps({"written": written}, indent=2))


def cmd_roundtrip(args):
    config = load_config(args.root)
    out_dir = config.results_dir / "roundtrip"
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for path in _query_paths(config):
        query = parse_query(path)
        out_path = _relative_output(out_dir, config.query_dir, path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(format_query(query))
        written.append(str(out_path))
    print(json.dumps({"written": written}, indent=2))


def cmd_fcir(args):
    config = load_config(args.root)
    cmd_sqir(args)
    sqir_dir = config.results_dir / "sqir" / config.language
    if not sqir_dir.exists():
        sqir_dir = config.results_dir / "sqir"
    out_path = config.results_dir / "fcir" / "corpus.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    result = write_corpus(sorted(sqir_dir.rglob("*.json")), out_path)
    print(
        json.dumps(
            {
                "output": str(out_path),
                "programs": len(result["programs"]),
                "programs_file": result["programs_path"],
                "provenance_file": result["provenance_path"],
            },
            indent=2,
        )
    )


def cmd_codeql_pack_fcir(args):
    config = load_config(args.root)
    pack_root = Path(args.pack_root) if args.pack_root else _default_codeql_pack_root(config)
    cwes = [int(item) for item in str(args.cwes).split(",") if item.strip()]
    result = write_codeql_pack_corpus(
        pack_root,
        config.results_dir / "fcir" / "codeql-pack",
        cwes=cwes,
        include_experimental=args.include_experimental,
    )
    print(
        json.dumps(
            {
                "programs": len(result["programs"]),
                "programs_file": result["programs_path"],
                "provenance_file": result["provenance_path"],
                "java_queries_root": result["java_queries_root"],
                "include_experimental": result["include_experimental"],
            },
            indent=2,
        )
    )


def cmd_codeql_discover(args):
    config = load_config(args.root)
    cwes = [int(item) for item in str(args.cwes).split(",") if item.strip()]
    result = discover_seed_queries(
        config,
        database_dir=args.database,
        output_dir=args.output_dir,
        cwes=cwes,
        include_experimental=args.include_experimental,
        specs=args.spec,
        analyze=not args.no_analyze,
        threads=args.threads,
        selection_policy=args.selection_policy,
    )
    print(
        json.dumps(
            {
                "output": str(Path(args.output_dir) if args.output_dir else config.results_dir / "seed-discovery"),
                "specs": len(result["specs"]),
                "queries": len(result["queries"]),
                "selected_seeds": len(result["selected_seeds"]),
                "score": result.get("score", {}).get("totals") if result.get("score") else None,
            },
            indent=2,
        )
    )


def cmd_generate_seeds(args):
    config = load_config(args.root)
    manifest_path = Path(args.manifest) if args.manifest else _default_seed_manifest(config)
    output_dir = (
        Path(args.output_dir)
        if args.output_dir
        else config.results_dir / "generated-query-profiles" / "bounded-java"
    )
    if args.validate_only:
        result = validate_seed_manifest(json.loads(manifest_path.read_text()))
    else:
        result = generate_seed_profile(manifest_path, output_dir)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok", True) else 1


def cmd_stitch(args):
    config = load_config(args.root)
    corpus_path = config.results_dir / "fcir" / "programs.json"
    if not corpus_path.exists():
        cmd_fcir(args)
    result = run_stitch(
        mode=getattr(args, "mode", None) or config.stitch_mode,
        corpus_path=corpus_path,
        output_path=config.results_dir / "stitch" / "candidates.json",
        fixture_path=config.root / "fixtures" / "stitch_candidates.json",
        stitch_binary=getattr(args, "stitch_binary", None),
        stitch_python=getattr(args, "stitch_python", None)
        or _default_stitch_python(config, getattr(args, "stitch_binary", None)),
        provenance_path=config.results_dir / "fcir" / "provenance.json",
        iterations=getattr(args, "iterations", 3),
        max_arity=getattr(args, "max_arity", 2),
        threads=getattr(args, "threads", 1),
    )
    print(json.dumps(result, indent=2))


def cmd_llm_propose(args):
    config = load_config(args.root)
    provenance_path = config.results_dir / "fcir" / "provenance.json"
    if not provenance_path.exists():
        cmd_fcir(args)
    output_path = config.results_dir / "llm" / "candidates.json"
    result = run_llm_propose(
        provenance_path=provenance_path,
        output_path=output_path,
        lilo_python=args.lilo_python or _default_stitch_python(config),
        fixture_path=args.fixture,
        model=args.model,
        max_tokens=args.max_tokens,
        lilo_input_path=args.lilo_input,
    )
    if args.merge:
        stitch_path = config.results_dir / "stitch" / "candidates.json"
        merged = _merge_candidate_files(stitch_path, output_path)
        stitch_path.parent.mkdir(parents=True, exist_ok=True)
        stitch_path.write_text(json.dumps(merged, indent=2))
        result["merged_candidates"] = str(stitch_path)
        result["merged_count"] = len(merged.get("candidates", []))
    print(json.dumps(result, indent=2))


def cmd_lilo_export(args):
    config = load_config(args.root)
    provenance_path = config.results_dir / "fcir" / "provenance.json"
    if not provenance_path.exists():
        cmd_fcir(args)
    output_path = Path(args.output) if args.output else config.results_dir / "lilo-loop" / "input.json"
    result = export_lilo_loop_input(config, output_path=output_path)
    print(
        json.dumps(
            {
                "output": str(output_path),
                "library_items": len(result.get("library_items", [])),
                "concepts": len(result.get("concepts", [])),
                "summary": result.get("summary", {}),
            },
            indent=2,
        )
    )


def cmd_lilo_loop(args):
    config = load_config(args.root)
    provenance_path = config.results_dir / "fcir" / "provenance.json"
    if not provenance_path.exists():
        cmd_fcir(args)
    output_dir = config.results_dir / "lilo-loop"
    input_path = Path(args.input) if args.input else output_dir / "input.json"
    if args.input:
        if not input_path.exists():
            raise RuntimeError("LILO loop input does not exist: {}".format(input_path))
    else:
        export_lilo_loop_input(config, output_path=input_path)
    fixture_path = args.fixture if args.mode == "fixture" else None
    if args.mode == "fixture" and not fixture_path:
        default_fixture = config.root / "fixtures" / "lilo_loop_outputs.json"
        if not default_fixture.exists():
            raise RuntimeError("--mode fixture requires --fixture when the default fixture is missing")
        fixture_path = default_fixture
    result = run_lilo_loop(
        provenance_path=provenance_path,
        output_dir=output_dir,
        input_path=input_path,
        mode=args.mode,
        lilo_python=args.lilo_python or _default_stitch_python(config),
        fixture_path=fixture_path,
        model=args.model,
        max_tokens=args.max_tokens,
        partition_mode=args.partition_mode,
        prompt_byte_budget=args.prompt_byte_budget,
        max_library_items=args.max_library_items,
        max_concepts_per_partition=args.max_concepts_per_partition,
        max_use_site_examples=args.max_use_site_examples,
    )
    if args.merge:
        stitch_path = config.results_dir / "stitch" / "candidates.json"
        merged = merge_candidate_files([result["output"], stitch_path], stitch_path)
        result["merged_candidates"] = str(stitch_path)
        result["merged_count"] = len(merged.get("candidates", []))
    print(json.dumps(result, indent=2))


def cmd_autodoc_eval(args):
    config = load_config(args.root)
    result = run_autodoc_eval(
        config,
        source_results=args.source_results,
        output_dir=args.output_dir,
        mode=args.mode,
        fixture_path=args.fixture,
        model=args.model,
        samples=args.samples,
        lilo_python=args.lilo_python or _default_stitch_python(config),
        cache_dir=args.cache_dir,
        include_provenance_rich=args.include_provenance_rich,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
    )
    print(json.dumps(result, indent=2))


def cmd_semantic_mine(args):
    config = load_config(args.root)
    provenance_paths = []
    sqir_provenance = config.results_dir / "fcir" / "provenance.json"
    if not sqir_provenance.exists():
        cmd_fcir(args)
    provenance_paths.append(sqir_provenance)

    pack_provenance = config.results_dir / "fcir" / "codeql-pack" / "provenance.json"
    if args.include_codeql_pack and not pack_provenance.exists():
        cwes = [int(item) for item in str(args.cwes).split(",") if item.strip()]
        pack_root = Path(args.pack_root) if args.pack_root else _default_codeql_pack_root(config)
        write_codeql_pack_corpus(
            pack_root,
            config.results_dir / "fcir" / "codeql-pack",
            cwes=cwes,
            include_experimental=args.include_experimental,
        )
    if pack_provenance.exists():
        provenance_paths.append(pack_provenance)

    output_path = config.results_dir / "semantic" / "candidates.json"
    result = mine_semantic_candidates(provenance_paths, output_path)
    if args.merge:
        stitch_path = config.results_dir / "stitch" / "candidates.json"
        merged = merge_candidate_files([stitch_path, output_path], stitch_path)
        result["merged_candidates"] = str(stitch_path)
        result["merged_count"] = len(merged.get("candidates", []))
    print(
        json.dumps(
            {
                "output": str(output_path),
                "concepts": result["concepts"],
                "candidates": len(result["candidates"]),
                "merged_candidates": result.get("merged_candidates"),
                "merged_count": result.get("merged_count"),
            },
            indent=2,
        )
    )


def cmd_validate(args):
    config = load_config(args.root)
    if not (config.results_dir / "sqir").exists():
        cmd_sqir(args)
    candidate_path = config.results_dir / "stitch" / "candidates.json"
    if not candidate_path.exists():
        cmd_stitch(args)
    result = validate_pipeline(
        config,
        candidate_path=candidate_path,
        decisions_path=config.results_dir / "validation" / "decisions.json",
    )
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def cmd_codeql_check(args):
    config = load_config(args.root)
    decisions_path = Path(args.decisions) if args.decisions else config.results_dir / "validation" / "decisions.json"
    if not decisions_path.exists():
        result = cmd_validate(args)
        if result:
            return result
    if not (config.results_dir / "rewritten").exists():
        result = cmd_rewrite(args)
        if result:
            return result
    result = run_codeql_check(
        config,
        decisions_path=decisions_path,
        query_dir=config.query_dir,
        rewritten_dir=config.results_dir / "rewritten",
        output_path=config.results_dir / "validation" / "codeql-check.json",
        target_language=config.language,
        final_only=getattr(args, "final_only", False),
    )
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def cmd_rewrite(args):
    config = load_config(args.root)
    decisions_path = config.results_dir / "validation" / "decisions.json"
    if not decisions_path.exists():
        result = cmd_validate(args)
        if result:
            return result
    result = rewrite_queries(
        decisions_path,
        config.query_dir,
        config.results_dir / "rewritten",
        target_language=config.language,
    )
    print(json.dumps(result, indent=2))


def cmd_db_create(args):
    config = load_config(args.root)
    result = create_database(
        config,
        source_root=args.source_root,
        database_dir=args.database,
        overwrite=args.overwrite,
        build_mode=args.build_mode,
        build_command=args.build_command,
    )
    print(json.dumps(result, indent=2))


def cmd_analyze(args):
    config = load_config(args.root)
    query_path = _analysis_query_path(config, args.queries)
    output_path = Path(args.output) if args.output else config.sarif_dir / "{}.sarif".format(args.queries)
    result = analyze_database(
        config,
        query_path=query_path,
        database_dir=args.database,
        output_path=output_path,
    )
    print(json.dumps(result, indent=2))


def cmd_db_bundle(args):
    config = load_config(args.root)
    result = bundle_database(
        config,
        database_dir=args.database,
        output_path=args.output,
        include_diagnostics=not args.no_diagnostics,
    )
    print(json.dumps(result, indent=2))


def cmd_score(args):
    config = load_config(args.root)
    sarif_path = Path(args.sarif or config.sarif_dir / "original.sarif")
    result = score_sarif(
        sarif_path,
        config.curated_subset_manifest,
        output_path=config.results_dir / "score" / (sarif_path.stem + ".json"),
    )
    print(json.dumps(result, indent=2))


def cmd_compare(args):
    config = load_config(args.root)
    result = compare_sarif(
        args.original,
        args.rewritten,
        manifest_path=config.curated_subset_manifest,
    )
    print(json.dumps(result, indent=2))
    return 0 if result["equivalent"] else 1


def cmd_report(args):
    config = load_config(args.root)
    output = write_report(config, config.results_dir / "report.md")
    print(json.dumps({"report": output}, indent=2))


def cmd_baseline(args):
    config = load_config(args.root)
    require_codeql(config)
    raise RuntimeError(
        "CodeQL is installed; use db-create and analyze so the target OWASP root and query set are explicit."
    )


def cmd_manifest(args):
    config = load_config(args.root)
    result = validate_manifest(
        config.curated_subset_manifest, config.owasp_root, config.selected_cwes
    )
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def build_parser():
    parser = argparse.ArgumentParser(description="CyberSTITCH PoC pipeline")
    parser.add_argument("--root", default=Path.cwd(), help="CyberSTITCH project root")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name, fn in [
        ("doctor", cmd_doctor),
        ("sqir", cmd_sqir),
        ("roundtrip", cmd_roundtrip),
        ("fcir", cmd_fcir),
        ("codeql-pack-fcir", cmd_codeql_pack_fcir),
        ("codeql-discover", cmd_codeql_discover),
        ("generate-seeds", cmd_generate_seeds),
        ("codeql-check", cmd_codeql_check),
        ("semantic-mine", cmd_semantic_mine),
        ("llm-propose", cmd_llm_propose),
        ("lilo-export", cmd_lilo_export),
        ("lilo-loop", cmd_lilo_loop),
        ("autodoc-eval", cmd_autodoc_eval),
        ("validate", cmd_validate),
        ("rewrite", cmd_rewrite),
        ("report", cmd_report),
        ("baseline", cmd_baseline),
        ("manifest", cmd_manifest),
    ]:
        command = subparsers.add_parser(name)
        command.set_defaults(func=fn)

    stitch = subparsers.add_parser("stitch")
    stitch.add_argument("--mode", choices=["offline", "live"], default=None)
    stitch.add_argument("--stitch-binary", default=None)
    stitch.add_argument(
        "--stitch-python",
        default=None,
        help="Python interpreter with stitch_core installed; defaults to the LILO conda env when present.",
    )
    stitch.add_argument("--iterations", type=int, default=3)
    stitch.add_argument("--max-arity", type=int, default=2)
    stitch.add_argument("--threads", type=int, default=1)
    stitch.set_defaults(func=cmd_stitch)

    llm_propose = subparsers.choices["llm-propose"]
    llm_propose.add_argument("--lilo-python", default=None)
    llm_propose.add_argument("--fixture", default=None)
    llm_propose.add_argument("--model", default=None)
    llm_propose.add_argument("--max-tokens", type=int, default=1200)
    llm_propose.add_argument("--lilo-input", default=None)
    llm_propose.add_argument("--merge", action="store_true")

    lilo_export = subparsers.choices["lilo-export"]
    lilo_export.add_argument("--output", default=None)

    lilo_loop = subparsers.choices["lilo-loop"]
    lilo_loop.add_argument("--mode", choices=["fixture", "live"], default="fixture")
    lilo_loop.add_argument("--fixture", default=None)
    lilo_loop.add_argument("--input", default=None)
    lilo_loop.add_argument("--lilo-python", default=None)
    lilo_loop.add_argument("--model", default=None)
    lilo_loop.add_argument("--max-tokens", type=int, default=1600)
    lilo_loop.add_argument("--partition-mode", choices=["auto", "off", "role"], default="auto")
    lilo_loop.add_argument("--prompt-byte-budget", type=int, default=45000)
    lilo_loop.add_argument("--max-library-items", type=int, default=0)
    lilo_loop.add_argument("--max-concepts-per-partition", type=int, default=0)
    lilo_loop.add_argument("--max-use-site-examples", type=int, default=2)
    lilo_loop.add_argument("--merge", action="store_true")

    autodoc_eval = subparsers.choices["autodoc-eval"]
    autodoc_eval.add_argument("--mode", choices=["fixture", "live", "replay"], default="fixture")
    autodoc_eval.add_argument("--source-results", default=None)
    autodoc_eval.add_argument("--output-dir", default=None)
    autodoc_eval.add_argument("--fixture", default=None)
    autodoc_eval.add_argument("--model", default="gpt-3.5-turbo")
    autodoc_eval.add_argument("--samples", type=int, default=3)
    autodoc_eval.add_argument("--lilo-python", default=None)
    autodoc_eval.add_argument("--cache-dir", default=None)
    autodoc_eval.add_argument("--max-tokens", type=int, default=900)
    autodoc_eval.add_argument("--temperature", type=float, default=0.2)
    autodoc_eval.add_argument("--include-provenance-rich", action="store_true")

    codeql_check = subparsers.choices["codeql-check"]
    codeql_check.add_argument("--decisions", default=None)
    codeql_check.add_argument(
        "--final-only",
        action="store_true",
        help="Compile only the final rewritten query profile, skipping isolated per-helper syntax checks.",
    )

    codeql_pack_fcir = subparsers.choices["codeql-pack-fcir"]
    codeql_pack_fcir.add_argument("--pack-root", default=None)
    codeql_pack_fcir.add_argument("--cwes", default="78,89")
    codeql_pack_fcir.add_argument("--include-experimental", action="store_true")

    codeql_discover = subparsers.choices["codeql-discover"]
    codeql_discover.add_argument("--database", default=None)
    codeql_discover.add_argument("--output-dir", default=None)
    codeql_discover.add_argument("--cwes", default="78,89")
    codeql_discover.add_argument("--include-experimental", action="store_true")
    codeql_discover.add_argument("--spec", action="append", default=None)
    codeql_discover.add_argument("--no-analyze", action="store_true")
    codeql_discover.add_argument("--threads", type=int, default=0)
    codeql_discover.add_argument("--selection-policy", choices=["all", "firing"], default="all")

    generate_seeds = subparsers.choices["generate-seeds"]
    generate_seeds.add_argument("--manifest", default=None)
    generate_seeds.add_argument("--output-dir", default=None)
    generate_seeds.add_argument("--validate-only", action="store_true")

    semantic_mine = subparsers.choices["semantic-mine"]
    semantic_mine.add_argument("--merge", action="store_true")
    semantic_mine.add_argument("--include-codeql-pack", action="store_true")
    semantic_mine.add_argument("--pack-root", default=None)
    semantic_mine.add_argument("--cwes", default="78,89")
    semantic_mine.add_argument("--include-experimental", action="store_true")

    db_create = subparsers.add_parser("db-create")
    db_create.add_argument("--source-root", default=None)
    db_create.add_argument("--database", default=None)
    db_create.add_argument("--overwrite", action="store_true")
    db_create.add_argument(
        "--build-mode",
        choices=["none", "autobuild", "manual"],
        default=None,
        help="CodeQL build mode. Ignored when --build-command is provided.",
    )
    db_create.add_argument("--build-command", default=None)
    db_create.set_defaults(func=cmd_db_create)

    analyze = subparsers.add_parser("analyze")
    analyze.add_argument(
        "--queries",
        choices=["original", "roundtrip", "rewritten"],
        default="original",
    )
    analyze.add_argument("--database", default=None)
    analyze.add_argument("--output", default=None)
    analyze.set_defaults(func=cmd_analyze)

    db_bundle = subparsers.add_parser("db-bundle")
    db_bundle.add_argument("--database", default=None)
    db_bundle.add_argument("--output", default=None)
    db_bundle.add_argument("--no-diagnostics", action="store_true")
    db_bundle.set_defaults(func=cmd_db_bundle)

    score = subparsers.add_parser("score")
    score.add_argument("--sarif", default=None)
    score.set_defaults(func=cmd_score)

    compare = subparsers.add_parser("compare")
    compare.add_argument("original")
    compare.add_argument("rewritten")
    compare.set_defaults(func=cmd_compare)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.func(args)
        return 0 if result is None else result
    except Exception as e:
        parser.exit(1, "error: {}: {}\n".format(type(e).__name__, e))


def _analysis_query_path(config, query_set):
    if query_set == "original":
        language_dir = config.query_dir / config.language
        return language_dir if language_dir.exists() else config.query_dir
    if query_set == "roundtrip":
        root = config.results_dir / "roundtrip"
        path = root / config.language if (root / config.language).exists() else root
        if not path.exists():
            raise RuntimeError("roundtrip queries are missing; run the roundtrip stage first")
        return path
    if query_set == "rewritten":
        root = config.results_dir / "rewritten" / "queries"
        path = root / config.language if (root / config.language).exists() else root
        if not path.exists():
            raise RuntimeError("rewritten queries are missing; run the rewrite stage first")
        return path
    raise ValueError("unknown query set {}".format(query_set))


def _file_language(path):
    text = Path(path).read_text()
    if re.search(r"^\s*import\s+java\s*$", text, re.MULTILINE):
        return "java"
    if re.search(r"^\s*import\s+javascript\s*$", text, re.MULTILINE):
        return "javascript"
    return "unknown"


def _default_codeql_pack_root(config):
    local_codeql = config.root.parent / "codeql"
    if local_codeql.exists():
        return local_codeql
    if config.codeql_binary:
        candidate = config.codeql_binary.parent
        if candidate.exists():
            return candidate
    raise RuntimeError(
        "CodeQL pack root was not provided and ../codeql was not found; pass --pack-root"
    )


def _default_seed_manifest(config):
    return config.root / "query_profiles" / "bounded-java" / "seed_manifest.json"


def _default_stitch_python(config, stitch_binary=None):
    if stitch_binary:
        return None
    env_value = os.environ.get("CYBERSTITCH_STITCH_PYTHON")
    if env_value:
        return env_value
    candidate = config.root.parent / "lilo_sec" / ".conda" / "envs" / "lilo" / "bin" / "python"
    if candidate.exists():
        return str(candidate)
    return None


def _merge_candidate_files(primary_path, secondary_path):
    candidates = []
    sources = []
    seen = set()
    for path in [Path(primary_path), Path(secondary_path)]:
        if not path.exists():
            continue
        data = json.loads(path.read_text())
        sources.append(data.get("source", str(path)))
        for candidate in data.get("candidates", []):
            key = (
                candidate.get("schema", ""),
                candidate.get("semantic_hash") or candidate.get("name", ""),
            )
            if key in seen:
                continue
            seen.add(key)
            candidates.append(candidate)
    return {
        "format": "cyberstitch-candidates-v2",
        "source": "merged",
        "sources": sources,
        "candidates": candidates,
    }


if __name__ == "__main__":
    raise SystemExit(main())
