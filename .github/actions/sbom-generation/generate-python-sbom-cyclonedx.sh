#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   generate-python-sbom-cyclonedx.sh <project_dir> <output_prefix>

PROJECT_DIR="${1:?project directory is required}"
OUTPUT_PREFIX="${2:?output prefix is required}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CYCLONEDX_BOM_VERSION="${CYCLONEDX_BOM_VERSION:-7.3.0}"
POETRY_VERSION="${POETRY_VERSION:-2.2.1}"
PYTHON_BIN="${PYTHON_BIN:-}"

log() {
	echo "[python-sbom] $*"
}

die() {
	echo "[python-sbom] ERROR: $*" >&2
	exit 1
}

resolve_python() {
	# Prefer python3 on runners, but allow callers to override via PYTHON_BIN.
	if [ -n "$PYTHON_BIN" ]; then
		command -v "$PYTHON_BIN" >/dev/null || die "Configured Python not found: $PYTHON_BIN"
		return
	fi

	if command -v python3 >/dev/null; then
		PYTHON_BIN="python3"
	elif command -v python >/dev/null; then
		PYTHON_BIN="python"
	else
		die "Python interpreter not found"
	fi
}

is_poetry_project() {
	[ -f "poetry.lock" ] || grep -q '^\[tool\.poetry\]' pyproject.toml 2>/dev/null
}

requirements_file() {
	# Match the same requirements*.txt convention used by ecosystem detection.
	find . -maxdepth 1 -type f -name 'requirements*.txt' | sort | head -n 1
}

install_tooling() {
	local packages=("cyclonedx-bom==$CYCLONEDX_BOM_VERSION")

	# Poetry is only needed for Poetry projects; requirements scans avoid it.
	if is_poetry_project; then
		packages+=("poetry==$POETRY_VERSION")
	fi

	log "Installing SBOM tooling"

	"$PYTHON_BIN" -m venv "$TOOL_VENV"
	TOOL_PYTHON="$TOOL_VENV/bin/python"

	"$TOOL_PYTHON" -m pip install --disable-pip-version-check --quiet "${packages[@]}"

	if is_poetry_project; then
		TOOL_POETRY="$TOOL_VENV/bin/poetry"
	fi
}

ensure_poetry_lock() {
	if [ ! -f "poetry.lock" ]; then
		log "poetry.lock not found; generating lock file"
		"$TOOL_POETRY" lock --no-interaction
	fi
}

generate_poetry_sbom() {
	log "Detected Poetry project"

	ensure_poetry_lock

	PROJECT_VENV="$(mktemp -d)"

	log "Installing Poetry dependencies"

	# Keep project dependencies isolated from the action tooling environment.
	export POETRY_VIRTUALENVS_CREATE=true
	export POETRY_VIRTUALENVS_PATH="$PROJECT_VENV"
	"$TOOL_POETRY" install --no-interaction --no-root

	PROJECT_PYTHON="$("$TOOL_POETRY" env info --executable)"

	log "Generating SBOM from installed Poetry environment"

	"$TOOL_PYTHON" -m cyclonedx_py environment \
		"$PROJECT_PYTHON" \
		--output-format JSON \
		--output-file "$OUTPUT_FILE"
}

generate_requirements_sbom() {
	local requirements="$1"

	log "Detected requirements project: ${requirements#./}"

	PROJECT_VENV="$(mktemp -d)"
	"$PYTHON_BIN" -m venv "$PROJECT_VENV"

	PROJECT_PYTHON="$PROJECT_VENV/bin/python"

	log "Installing requirements"

	# Install into a temporary environment so cyclonedx-py can inspect resolved deps.
	"$PROJECT_PYTHON" -m pip install --disable-pip-version-check --quiet --upgrade pip
	"$PROJECT_PYTHON" -m pip install --disable-pip-version-check --quiet -r "$requirements"

	log "Generating SBOM from installed environment"

	"$TOOL_PYTHON" -m cyclonedx_py environment \
		"$PROJECT_PYTHON" \
		--output-format JSON \
		--output-file "$OUTPUT_FILE"
}

verify_sbom() {
	local sbom_file="$1"
	local python_bin="$2"

	[ -f "$sbom_file" ] || die "SBOM output missing: $sbom_file"

	local component_count
	component_count="$(
		"$python_bin" - "$sbom_file" <<'PY'
import json, sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

print(len(data.get("components") or []))
PY
	)"

	if [ "$component_count" -eq 0 ]; then
		die "SBOM contains zero components: $sbom_file"
	fi

	log "SBOM contains $component_count components"
}

[ -d "$PROJECT_DIR" ] || die "Project directory does not exist: $PROJECT_DIR"
resolve_python

mkdir -p "$(dirname "$OUTPUT_PREFIX")"

OUTPUT_FILE="$(cd "$(dirname "$OUTPUT_PREFIX")" && pwd)/$(basename "$OUTPUT_PREFIX").cyclonedx.json"
GITHUB_FILE="$(cd "$(dirname "$OUTPUT_PREFIX")" && pwd)/$(basename "$OUTPUT_PREFIX").github.json"

TOOL_VENV="$(mktemp -d)"
PROJECT_VENV=""

cleanup() {
	rm -rf "$TOOL_VENV"
	[ -n "${PROJECT_VENV}" ] && rm -rf "$PROJECT_VENV"
}
trap cleanup EXIT

pushd "$PROJECT_DIR" >/dev/null

install_tooling

if is_poetry_project; then
	generate_poetry_sbom
elif requirements="$(requirements_file)" && [ -n "$requirements" ]; then
	generate_requirements_sbom "$requirements"
else
	die "No supported dependency manifest found (poetry.lock, pyproject.toml, or requirements*.txt)"
fi

log "Generating GitHub dependency snapshot from installed environment"

"$PROJECT_PYTHON" "$SCRIPT_DIR/../refresh-dependency-graph/generate-python-snapshot.py" \
	"$PROJECT_DIR" \
	"$GITHUB_FILE"

popd >/dev/null

verify_sbom "$OUTPUT_FILE" "$TOOL_PYTHON"

log "SBOM written to: $OUTPUT_FILE"
