#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   generate-sbom.sh <source> <output_prefix> [ecosystems_json]
#
# Example:
#   generate-sbom.sh "dir:." "filesystem"
#
# Produces:
#   filesystem.cyclonedx.json
#   filesystem.spdx.json

SOURCE="${1:?source is required}"
OUTPUT_PREFIX="${2:?output prefix is required}"
ECOSYSTEMS_JSON="${3:-[]}"
OUTPUT_DIR="$(dirname "$OUTPUT_PREFIX")"

if [ "$OUTPUT_DIR" != "." ]; then
	mkdir -p "$OUTPUT_DIR"
fi

log() {
	echo "[sbom] $*"
}

generate_cyclonedx_sbom() {
	local source="$1"

	log "Generating CycloneDX SBOM with Syft"

	syft "$source" \
		--output "cyclonedx-json=${OUTPUT_PREFIX}.cyclonedx.json"
}

source_dir() {
	local source="$1"
	echo "${source#dir:}"
}

is_python_scan() {
	jq -e 'index("python") != null' <<<"$ECOSYSTEMS_JSON" >/dev/null
}

generate_python_cyclonedx_sbom() {
	local source="$1"
	local dir
	dir="$(source_dir "$source")"

	log "Generating Python CycloneDX SBOM with cyclonedx-py"

	if [ -f "$dir/poetry.lock" ] || [ -f "$dir/pyproject.toml" ]; then
		(
			cd "$dir"
			cyclonedx-py poetry \
				--output-format JSON \
				--output-file "$OLDPWD/${OUTPUT_PREFIX}.cyclonedx.json"
		)
		return
	fi

	local requirements_file=""
	for candidate in "$dir"/requirements*.lock "$dir"/requirements*.txt; do
		if [ -f "$candidate" ]; then
			requirements_file="$candidate"
			break
		fi
	done

	if [ -z "$requirements_file" ]; then
		echo "No Python requirements or Poetry manifest found in $dir" >&2
		exit 1
	fi

	cyclonedx-py requirements \
		--output-format JSON \
		--output-file "${OUTPUT_PREFIX}.cyclonedx.json" \
		"$requirements_file"
}

generate_spdx_sbom() {
	local source="$1"

	log "Generating SPDX JSON 2.2 SBOM with Syft"

	syft "$source" \
		--output "spdx-json@2.2=${OUTPUT_PREFIX}.spdx.json"
}

if is_python_scan; then
	generate_python_cyclonedx_sbom "$SOURCE"
else
	generate_cyclonedx_sbom "$SOURCE"
fi
generate_spdx_sbom "$SOURCE"

log "SBOM generation completed"

ls -lh \
	"${OUTPUT_PREFIX}.cyclonedx.json" \
	"${OUTPUT_PREFIX}.spdx.json" 2>/dev/null || true


log "Validating SPDX package metadata"

jq '
[
	.packages[]
	| {
		name,
		versionInfo,
		purl: [
			.externalRefs[]?
			| select(.referenceType=="purl")
			| .referenceLocator
		]
	}
]
| .[0:10]
' "${OUTPUT_PREFIX}.spdx.json"