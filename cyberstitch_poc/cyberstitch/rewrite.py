import json
import re
from pathlib import Path


LANGUAGE_IMPORTS = {
    "javascript": [
        "import javascript",
        "import semmle.javascript.dataflow.TaintTracking",
    ],
    "java": [
        "import java",
        "import semmle.code.java.dataflow.TaintTracking",
        "import semmle.code.java.dataflow.FlowSources",
        "import semmle.code.java.dataflow.ExternalFlow",
        "import semmle.code.java.security.CommandLineQuery",
        "import semmle.code.java.security.QueryInjection",
        "import semmle.code.java.security.Sanitizers",
        "import semmle.code.java.security.SqlInjectionQuery",
        "import semmle.code.java.security.TaintedEnvironmentVariableQuery",
    ],
}


def _helper_text(language, accepted):
    imports = LANGUAGE_IMPORTS.get(language, [])
    lines = imports + ["", "module {} {{".format(_helper_module(accepted))]
    for item in accepted:
        body = item["candidate"]["body"].strip()
        for line in body.splitlines():
            lines.append("  {}".format(line.rstrip()))
        lines.append("")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def _helper_module(accepted):
    modules = {
        item["candidate"].get("helper_module", "CyberStitchHelpers")
        for item in accepted
    }
    if len(modules) != 1:
        raise ValueError("accepted candidates for one language must use one helper module")
    return next(iter(modules))


def _helper_import(language):
    return "cyberstitch_helpers_java" if language == "java" else "cyberstitch_helpers"


def _replace_predicate_body(text, predicate_name, helper_module, helper_predicate):
    pattern = re.compile(
        r"(predicate\s+{}\s*\((.*?)\)\s*\{{)(.*?)(^\s*\}})".format(
            re.escape(predicate_name)
        ),
        re.DOTALL | re.MULTILINE,
    )

    def replace(match):
        params = [
            part.strip().rsplit(" ", 1)[-1]
            for part in match.group(2).split(",")
            if part.strip()
        ]
        args = ", ".join(params)
        return "{}\n    {}::{}({})\n  }}".format(
            match.group(1), helper_module, helper_predicate, args
        )

    return pattern.sub(replace, text, count=1)


def rewrite_queries(decisions_path, query_dir, output_dir, target_language=None):
    with open(decisions_path) as handle:
        decisions = json.load(handle)["decisions"]
    accepted = [item for item in decisions if item["accepted"]]

    output_dir = Path(output_dir)
    rewritten_dir = output_dir / "queries"
    rewritten_dir.mkdir(parents=True, exist_ok=True)

    by_language = {}
    for item in accepted:
        language = item["candidate"].get("language", "javascript")
        by_language.setdefault(language, []).append(item)

    helpers = {}
    query_helpers = {}
    for helper_language, items in by_language.items():
        helper_name = "{}.qll".format(_helper_import(helper_language))
        helper_text = _helper_text(helper_language, items)
        helper_path = output_dir / helper_name
        helper_path.write_text(helper_text)
        query_helper_dir = rewritten_dir / helper_language if helper_language == "java" else rewritten_dir
        query_helper_dir.mkdir(parents=True, exist_ok=True)
        query_helper_path = query_helper_dir / helper_name
        query_helper_path.write_text(helper_text)
        helpers[helper_language] = str(helper_path)
        query_helpers[helper_language] = str(query_helper_path)

    query_dir = Path(query_dir)
    written = []
    for query_path in sorted(query_dir.rglob("*.ql")):
        relative = query_path.relative_to(query_dir).as_posix()
        query_language = _language_for_query(query_path)
        if target_language and target_language != "all" and query_language != target_language:
            continue
        text = query_path.read_text()
        import_name = _helper_import(query_language)
        touched = False

        for item in accepted:
            candidate = item["candidate"]
            if candidate.get("language", "javascript") != query_language:
                continue
            for use_site in candidate.get("use_sites", []):
                if use_site.get("query") not in {relative, query_path.name}:
                    continue
                if "import {}".format(import_name) not in text:
                    text = _insert_import(text, import_name)
                text = _replace_predicate_body(
                    text,
                    use_site["predicate"],
                    candidate.get("helper_module", "CyberStitchHelpers"),
                    candidate["predicate"],
                )
                touched = True

        out_path = rewritten_dir / relative
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text)
        written.append(str(out_path))

    helper = next(iter(helpers.values()), "")
    return {
        "helper": helper,
        "helpers": helpers,
        "query_helpers": query_helpers,
        "queries": str(rewritten_dir),
        "written": written,
    }


def _language_for_query(path):
    text = Path(path).read_text()
    if re.search(r"^\s*import\s+java\s*$", text, re.MULTILINE):
        return "java"
    if re.search(r"^\s*import\s+javascript\s*$", text, re.MULTILINE):
        return "javascript"
    return "unknown"


def _insert_import(text, import_name):
    import_matches = list(re.finditer(r"^import .+$", text, re.MULTILINE))
    if not import_matches:
        return "import {}\n{}".format(import_name, text)
    last_import = import_matches[-1]
    return text[: last_import.end()] + "\nimport " + import_name + text[last_import.end() :]
