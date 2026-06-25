#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   generate-python-sbom-cyclonedx.sh <project_dir> <output_prefix>
#
# Produces:
#   <output_prefix>.cyclonedx.json

PROJECT_DIR="${1:?project directory is required}"
OUTPUT_PREFIX="${2:?output prefix is required}"

CYCLONEDX_BOM_VERSION="${CYCLONEDX_BOM_VERSION:-7.3.0}"
PYTHON_BIN="${PYTHON_BIN:-}"

log() {
	echo "[python-sbom] $*"
}

die() {
	echo "[python-sbom] ERROR: $*" >&2
	exit 1
}

resolve_python() {
	if [ -n "$PYTHON_BIN" ]; then
		command -v "$PYTHON_BIN" >/dev/null ||
			die "Configured Python not found: $PYTHON_BIN"
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
	[ -f poetry.lock ] ||
	{
		[ -f pyproject.toml ] &&
		grep -q '^\[tool\.poetry\]' pyproject.toml
	}
}

requirements_file() {
	find . -maxdepth 1 -type f -name 'requirements*.txt' | sort | head -n 1
}

install_tooling() {
	log "Installing cyclonedx-py"

	"$PYTHON_BIN" -m venv "$TOOL_VENV"
	TOOL_PYTHON="$TOOL_VENV/bin/python"

	"$TOOL_PYTHON" -m pip install \
		--disable-pip-version-check \
		--quiet \
		"cyclonedx-bom==$CYCLONEDX_BOM_VERSION"
}

generate_from_poetry() {
	[ -f poetry.lock ] ||
		die "poetry.lock missing; deterministic Poetry SBOM requires a lock file"

	log "Generating CycloneDX SBOM from poetry.lock"

	"$TOOL_PYTHON" -m cyclonedx_py poetry \
		--output-format JSON \
		--output-file "$CYCLONEDX_OUTPUT"
}

generate_from_requirements() {
	local requirements="$1"

	log "Generating CycloneDX SBOM from ${requirements#./}"

	"$TOOL_PYTHON" -m cyclonedx_py requirements \
		"$requirements" \
		--output-format JSON \
		--output-file "$CYCLONEDX_OUTPUT"
}

verify_cyclonedx() {
	[ -s "$CYCLONEDX_OUTPUT" ] ||
		die "CycloneDX output missing or empty: $CYCLONEDX_OUTPUT"

	local components
	local dependencies

	components="$(jq '.components | length' "$CYCLONEDX_OUTPUT")"
	dependencies="$(jq '.dependencies | length' "$CYCLONEDX_OUTPUT")"

	[ "$components" -gt 0 ] ||
		die "CycloneDX contains no components"

	log "CycloneDX components: $components"
	log "CycloneDX dependency graph entries: $dependencies"
}

[ -d "$PROJECT_DIR" ] ||
	die "Project directory does not exist: $PROJECT_DIR"

resolve_python

mkdir -p "$(dirname "$OUTPUT_PREFIX")"
CYCLONEDX_OUTPUT="$(
	cd "$(dirname "$OUTPUT_PREFIX")" &&
	pwd
)/$(basename "$OUTPUT_PREFIX").cyclonedx.json"

TOOL_VENV="$(mktemp -d)"

cleanup() {
	rm -rf "$TOOL_VENV"
}

trap cleanup EXIT

pushd "$PROJECT_DIR" >/dev/null

install_tooling

if is_poetry_project; then
	generate_from_poetry
elif requirements="$(requirements_file)" && [ -n "$requirements" ]; then
	generate_from_requirements "$requirements"
else
	die "No supported dependency manifest found"
fi

popd >/dev/null

verify_cyclonedx

log "CycloneDX dependency SBOM: $CYCLONEDX_OUTPUT"
