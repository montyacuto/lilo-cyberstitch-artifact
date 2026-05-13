#!/usr/bin/env bash
set -euo pipefail

SOURCE="${BASH_SOURCE[0]}"
if command -v readlink >/dev/null 2>&1; then
  SOURCE="$(readlink -f "$SOURCE")"
fi
ROOT="$(cd "$(dirname "$SOURCE")" && pwd)"
export PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE:-1}"

usage() {
  cat <<'EOF'
Usage: ./artifact <command> [args...]

Common commands:
  menu              Open the combined LILO/CyberSTITCH TUI.
  tasks             List registered artifact tasks.
  run-task <id>     Run one registered task.
  verify            Run default non-destructive verification.
  package-smoke     Run package-only smoke checks that need no LILO/CyberSTITCH env.
  smoke             Run default offline smoke checks after environments are prepared.
  reproduce         Run a suite in fixture/replay/live mode.
  package-plan      Print package plan pointers.
  package-verify    Verify selected package inputs.
  package-stage     Write a package staging manifest; copying is opt-in.
  report            Print summary/report pointers.

Existing lilo_sec/scripts/artifact.sh commands are also accepted.
EOF
}

cmd="${1:-menu}"
if [ "$#" -gt 0 ]; then
  shift
fi

case "$cmd" in
  menu)
    cd "$ROOT/lilo_sec"
    exec scripts/lilo "$@"
    ;;
  tasks|run-task|verify|package-smoke|smoke|reproduce|package-plan|package-verify|package-stage|report)
    exec "$ROOT/lilo_sec/scripts/artifact_runner.py" "$cmd" "$@"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    cd "$ROOT/lilo_sec"
    exec scripts/artifact.sh "$cmd" "$@"
    ;;
esac
