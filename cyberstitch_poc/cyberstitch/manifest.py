import csv
import json
from pathlib import Path


REQUIRED_CASE_FIELDS = {
    "test_id",
    "file",
    "cwe",
    "category",
    "expected_vulnerable",
    "rationale",
    "abstraction_target",
}


def load_manifest(path):
    path = Path(path)
    with path.open() as handle:
        data = json.load(handle)
    return data


def manifest_cases(path):
    return load_manifest(path).get("cases", [])


def validate_manifest(manifest_path, owasp_root, selected_cwes=None):
    manifest_path = Path(manifest_path)
    owasp_root = Path(owasp_root)
    selected = set(selected_cwes or [])
    errors = []
    warnings = []

    if not manifest_path.exists():
        return {
            "ok": False,
            "errors": ["missing curated manifest: {}".format(manifest_path)],
            "warnings": warnings,
            "cases": [],
        }

    manifest = load_manifest(manifest_path)
    cases = manifest.get("cases", [])
    seen = set()
    expected = _load_expected_results(manifest, owasp_root, warnings)

    for index, case in enumerate(cases):
        prefix = "case {} ({})".format(index, case.get("test_id", "<missing>"))
        missing = sorted(REQUIRED_CASE_FIELDS - set(case))
        if missing:
            errors.append("{} missing fields: {}".format(prefix, ", ".join(missing)))
            continue

        test_id = str(case["test_id"])
        if test_id in seen:
            errors.append("duplicate test_id: {}".format(test_id))
        seen.add(test_id)

        cwe = int(case["cwe"])
        if selected and cwe not in selected:
            errors.append("{} has unselected CWE {}".format(prefix, cwe))

        case_file = owasp_root / case["file"]
        if not case_file.exists():
            errors.append("{} missing file: {}".format(prefix, case_file))

        if test_id in expected:
            expected_row = expected[test_id]
            if expected_row.get("category") != case["category"]:
                errors.append(
                    "{} category mismatch: manifest={} expected={}".format(
                        prefix, case["category"], expected_row.get("category")
                    )
                )
            if int(expected_row.get("cwe", -1)) != cwe:
                errors.append(
                    "{} CWE mismatch: manifest={} expected={}".format(
                        prefix, cwe, expected_row.get("cwe")
                    )
                )
            expected_vulnerable = _bool(expected_row.get("vulnerable"))
            if expected_vulnerable != bool(case["expected_vulnerable"]):
                errors.append(
                    "{} vulnerability mismatch: manifest={} expected={}".format(
                        prefix,
                        bool(case["expected_vulnerable"]),
                        expected_vulnerable,
                    )
                )

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "cases": cases,
        "manifest": str(manifest_path),
        "owasp_root": str(owasp_root),
    }


def case_by_file(cases):
    return {Path(case["file"]).name: case for case in cases}


def case_for_uri(cases, uri):
    uri = uri.replace("\\", "/")
    for case in cases:
        file_name = Path(case["file"]).name
        if uri.endswith(case["file"]) or uri.endswith(file_name):
            return case
    return None


def _load_expected_results(manifest, owasp_root, warnings):
    benchmark = manifest.get("benchmark", {})
    expected_name = benchmark.get("expected_results")
    candidates = []
    if expected_name:
        candidates.append(Path(owasp_root) / expected_name)
    candidates.extend(sorted(Path(owasp_root).glob("expectedresults-*.csv")))
    for path in candidates:
        if path.exists():
            return _read_expected_csv(path)
    warnings.append("no expectedresults-*.csv found under {}".format(owasp_root))
    return {}


def _read_expected_csv(path):
    rows = {}
    with Path(path).open(newline="") as handle:
        lines = [
            _normalize_expected_header(line)
            for line in handle
            if line.strip() and not line.lstrip().startswith("# Benchmark")
        ]
        reader = csv.DictReader(lines)
        for raw in reader:
            lowered = {
                str(key).strip().lower(): str(value or "").strip()
                for key, value in raw.items()
                if key is not None
            }
            test_id = (
                lowered.get("test name")
                or lowered.get("test_id")
                or lowered.get("test")
                or lowered.get("name")
            )
            if not test_id:
                continue
            rows[test_id] = {
                "category": lowered.get("category"),
                "vulnerable": lowered.get("real vulnerability")
                or lowered.get("expected_vulnerable")
                or lowered.get("vulnerable"),
                "cwe": lowered.get("cwe"),
            }
    return rows


def _normalize_expected_header(line):
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return stripped[1:].lstrip()
    return line


def _bool(value):
    return str(value).strip().lower() in {"true", "1", "yes", "y"}
