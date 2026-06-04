#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
	cat <<'EOF'
Usage: scripts/dependency-review.sh [--out FILE]

Creates a Markdown dependency/license inventory from Go module metadata. The
script downloads modules into the configured module cache, lists every
non-main module, and fails if any module has no obvious top-level license file.

Options:
  --out FILE  Write Markdown output to FILE. Default: stdout.
  --help      Show this help.
EOF
}

output_file=""
while [[ $# -gt 0 ]]; do
	case "$1" in
	--out)
		if [[ $# -lt 2 ]]; then
			echo "--out requires a value" >&2
			exit 2
		fi
		output_file=$2
		shift 2
		;;
	--help|-h)
		usage
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		usage >&2
		exit 2
		;;
	esac
done

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

markdown_escape() {
	local value=$1
	value=${value//\\/\\\\}
	value=${value//|/\\|}
	printf '%s' "$value"
}

license_files_for_dir() {
	local module_dir=$1
	find "$module_dir" -maxdepth 1 -type f \( \
		-iname 'license' -o \
		-iname 'license.*' -o \
		-iname 'licence' -o \
		-iname 'licence.*' -o \
		-iname 'copying' -o \
		-iname 'copying.*' -o \
		-iname 'notice' -o \
		-iname 'notice.*' \
	\) -printf '%f\n' 2>/dev/null | sort | paste -sd ',' -
}

emit_report() {
	local generated_at=$1
	local module_rows=$2
	local missing_count=$3
	local module_count=$4

	{
		echo "# Runtime Guard Dependency Review"
		echo
		echo "Generated: $generated_at"
		echo
		echo "Module count: $module_count"
		echo "Modules missing top-level license files: $missing_count"
		echo
		echo "| Module | Version | Kind | License files |"
		echo "| --- | --- | --- | --- |"
		printf '%s' "$module_rows"
	}
}

require_command date
require_command find
require_command go
require_command paste
require_command sort

export GOCACHE="${GOCACHE:-/tmp/runtime-guard-gocache}"
export GOMODCACHE="${GOMODCACHE:-/tmp/runtime-guard-gomodcache}"

go mod download all

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
module_rows=""
missing_count=0
module_count=0

while IFS=$'\t' read -r module_path module_version module_kind module_dir; do
	if [[ -z "$module_path" ]]; then
		continue
	fi
	module_count=$((module_count + 1))
	license_files="missing"
	if [[ -n "$module_dir" && -d "$module_dir" ]]; then
		found="$(license_files_for_dir "$module_dir")"
		if [[ -n "$found" ]]; then
			license_files=$found
		fi
	fi
	if [[ "$license_files" == "missing" ]]; then
		missing_count=$((missing_count + 1))
	fi
	module_rows+="| $(markdown_escape "$module_path") | $(markdown_escape "$module_version") | $(markdown_escape "$module_kind") | $(markdown_escape "$license_files") |"$'\n'
done < <(go list -m -f '{{if not .Main}}{{.Path}}{{"\t"}}{{.Version}}{{"\t"}}{{if .Indirect}}indirect{{else}}direct{{end}}{{"\t"}}{{.Dir}}{{end}}' all)

if [[ -n "$output_file" ]]; then
	emit_report "$generated_at" "$module_rows" "$missing_count" "$module_count" >"$output_file"
else
	emit_report "$generated_at" "$module_rows" "$missing_count" "$module_count"
fi

if [[ "$missing_count" -ne 0 ]]; then
	echo "dependency review found modules without top-level license files: $missing_count" >&2
	exit 1
fi
