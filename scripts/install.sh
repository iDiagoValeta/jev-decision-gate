#!/usr/bin/env bash
# install.sh — one-command installer for jev-decision-gate.
# Usage: ./scripts/install.sh [--global|--project] [--log-file PATH] [--key-env]
set -euo pipefail

SCOPE="--project"
LOG_FILE=""
PRINT_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --global) SCOPE="--global"; shift ;;
    --project) SCOPE="--project"; shift ;;
    --log-file) LOG_FILE="$2"; shift 2 ;;
    --print-paths) PRINT_ONLY=1; shift ;;
    *) echo "Unknown flag: $1" >&2; exit 1 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLUGIN_DIR="$ROOT/plugin/jev-decision-gate"
DEFAULT_LOG="$ROOT/decisions-plugin.jsonl"
LOG_FILE="${LOG_FILE:-$DEFAULT_LOG}"

if [ "$PRINT_ONLY" = 1 ]; then
  echo "plugin=$PLUGIN_DIR"
  echo "log=$LOG_FILE"
  echo "scope=$SCOPE"
  exit 0
fi

echo "==> python deps"
python3 -m pip install -e "$ROOT" 2>&1 | tail -1

if command -v npm >/dev/null 2>&1; then
  echo "==> node deps"
  npm --prefix "$ROOT/plugin" install --no-audit --no-fund 2>&1 | tail -1
else
  echo "WARN: npm not found, skipping node install" >&2
fi

if [ "$SCOPE" = "--global" ]; then
  CONFIG="$HOME/.config/opencode/opencode.json"
else
  CONFIG="$PWD/opencode.jsonc"
fi

python3 - "$CONFIG" "$PLUGIN_DIR" "$LOG_FILE" <<'EOF'
import json, sys
config_path, plugin_pkg, log_file = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(config_path) as f:
        cfg = json.load(f)
except FileNotFoundError:
    cfg = {}
plugins = cfg.get("plugins", [])
plugins = [p for p in plugins if not (
    (isinstance(p, dict) and "jev-decision-gate" in str(p.get("package", ""))) or
    (isinstance(p, str) and "jev-decision-gate" in p))]
plugins.append({"package": plugin_pkg, "options": {"logFile": log_file}})
cfg["plugins"] = plugins
if "permission" not in cfg:
    cfg["permission"] = "ask"
elif cfg["permission"] != "ask":
    print(f"WARN: permission is {cfg['permission']!r}, not left alone — "
          "the gate needs \"permission\": \"ask\" to receive permission.asked "
          "events at all; set it yourself if you want the gate to do anything.",
          file=sys.stderr)
with open(config_path, "w") as f:
    json.dump(cfg, f, indent=2)
print(f"wrote {config_path}")
EOF

echo "==> verify"
TYPESAFE_API_KEY="${TYPESAFE_API_KEY:-}" JEV_GATE_LOG="$LOG_FILE" \
  python3 -m jev_gate.doctor || echo "WARN: doctor found issues (see above)" >&2
echo "Done. Log: $LOG_FILE"
