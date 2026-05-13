import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Config:
    root: Path
    language: str
    query_dir: Path
    benchmark_dir: Path
    owasp_root: Path
    curated_subset_manifest: Path
    results_dir: Path
    stitch_mode: str = "offline"
    codeql_binary: Optional[Path] = None
    codeql_build_mode: str = "none"
    codeql_build_command: Optional[str] = None
    codeql_database_dir: Path = None
    sarif_dir: Path = None
    selected_cwes: list[int] = field(default_factory=lambda: [78, 89])
    query_glob: str = "**/*.ql"


def _parse_simple_yaml(path):
    data = {}
    if not path.exists():
        return data
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip().strip("\"'")
    return data


def _split_list(value, default):
    if value is None:
        return list(default)
    if isinstance(value, list):
        items = value
    else:
        text = str(value).strip()
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        items = [item.strip().strip("\"'") for item in text.split(",")]
    return [int(item) for item in items if str(item).strip()]


def load_config(root=None, config_path=None):
    root = Path(root or Path.cwd()).resolve()
    config_path = Path(config_path or root / "cyberstitch.yml")
    data = _parse_simple_yaml(config_path)
    results_dir_override = os.environ.get("CYBERSTITCH_RESULTS_DIR")

    def rel_path(key, default, env_key=None):
        value = os.environ.get(env_key) if env_key else None
        value = value or data.get(key, default)
        return (root / value).resolve()

    results_dir = rel_path("results_dir", "results", "CYBERSTITCH_RESULTS_DIR")
    codeql_binary = (
        os.environ.get("CYBERSTITCH_CODEQL")
        or os.environ.get("CODEQL")
        or data.get("codeql_binary")
    )
    codeql_build_command = (
        os.environ.get("CYBERSTITCH_CODEQL_BUILD_COMMAND")
        or data.get("codeql_build_command")
    )
    codeql_database_dir = (
        (root / os.environ["CYBERSTITCH_CODEQL_DATABASE_DIR"]).resolve()
        if os.environ.get("CYBERSTITCH_CODEQL_DATABASE_DIR")
        else (
            results_dir / "codeql-dbs"
            if results_dir_override
            else rel_path("codeql_database_dir", "results/codeql-dbs")
        )
    )
    sarif_dir = (
        (root / os.environ["CYBERSTITCH_SARIF_DIR"]).resolve()
        if os.environ.get("CYBERSTITCH_SARIF_DIR")
        else (
            results_dir / "sarif"
            if results_dir_override
            else rel_path("sarif_dir", "results/sarif")
        )
    )

    return Config(
        root=root,
        language=os.environ.get("CYBERSTITCH_LANGUAGE", data.get("language", "java")),
        query_dir=rel_path("query_dir", "queries", "CYBERSTITCH_QUERY_DIR"),
        benchmark_dir=rel_path("benchmark_dir", "benchmarks/js"),
        owasp_root=Path(
            os.environ.get(
                "CYBERSTITCH_OWASP_ROOT",
                str(rel_path("owasp_root", "benchmarks/owasp-fixture")),
            )
        ).resolve(),
        curated_subset_manifest=rel_path(
            "curated_subset_manifest",
            "benchmarks/owasp_curated_subset.json",
            "CYBERSTITCH_CURATED_SUBSET_MANIFEST",
        ),
        results_dir=results_dir,
        stitch_mode=data.get("stitch_mode", "offline"),
        codeql_binary=Path(codeql_binary).resolve() if codeql_binary else None,
        codeql_build_mode=os.environ.get(
            "CYBERSTITCH_CODEQL_BUILD_MODE",
            data.get("codeql_build_mode", "none"),
        ),
        codeql_build_command=codeql_build_command,
        codeql_database_dir=codeql_database_dir,
        sarif_dir=sarif_dir,
        selected_cwes=_split_list(data.get("selected_cwes"), [78, 89]),
        query_glob=os.environ.get("CYBERSTITCH_QUERY_GLOB", data.get("query_glob", "**/*.ql")),
    )
