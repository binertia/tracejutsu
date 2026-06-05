#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
	cat <<'EOF'
Usage: scripts/validation-bundle.sh [--name NAME] [--out DIR] [--supporting FILE] LOGFILE [...]

Collects Runtime Guard validation logs into a small release-evidence bundle.
The bundle includes:
  - copied log files
  - optional supporting evidence files that are copied but not pass/fail checked
  - host fingerprint captured on the machine running this command
  - repository metadata
  - validation-summary output
  - SHA256 checksums
  - a .tar.gz archive

The script exits nonzero if scripts/validation-summary.sh marks any supplied
log as failed, but it still writes the bundle for inspection first.

Options:
  --name NAME        Bundle directory/archive name. Default: timestamp-hostname.
  --out DIR          Output directory. Default: validation-artifacts.
  --supporting FILE  Copy FILE into supporting/ without validation-summary checks.
                     Repeat for container workload logs, event samples, etc.
  --help             Show this help.
EOF
}

bundle_name=""
out_dir="validation-artifacts"
logs=()
supporting_files=()

while [[ $# -gt 0 ]]; do
	case "$1" in
	--name)
		if [[ $# -lt 2 ]]; then
			echo "--name requires a value" >&2
			exit 2
		fi
		bundle_name=$2
		shift 2
		;;
	--out)
		if [[ $# -lt 2 ]]; then
			echo "--out requires a value" >&2
			exit 2
		fi
		out_dir=$2
		shift 2
		;;
	--supporting)
		if [[ $# -lt 2 ]]; then
			echo "--supporting requires a value" >&2
			exit 2
		fi
		supporting_files+=("$2")
		shift 2
		;;
	--help|-h)
		usage
		exit 0
		;;
	--)
		shift
		while [[ $# -gt 0 ]]; do
			logs+=("$1")
			shift
		done
		;;
	-*)
		echo "unknown argument: $1" >&2
		usage >&2
		exit 2
		;;
	*)
		logs+=("$1")
		shift
		;;
	esac
done

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

sanitize_name() {
	local name=$1
	printf '%s' "$name" | tr -c 'A-Za-z0-9._+-' '-'
}

require_command cp
require_command date
require_command hostname
require_command mkdir
require_command sha256sum
require_command tar
require_command tr

if [[ "${#logs[@]}" -eq 0 ]]; then
	usage >&2
	exit 2
fi

for log in "${logs[@]}"; do
	if [[ ! -r "$log" ]]; then
		echo "cannot read log file: $log" >&2
		exit 1
	fi
done
for file in "${supporting_files[@]}"; do
	if [[ ! -r "$file" ]]; then
		echo "cannot read supporting file: $file" >&2
		exit 1
	fi
done

source "$repo_root/scripts/systemd-helper-lib.sh"

if [[ -z "$bundle_name" ]]; then
	bundle_name="$(date -u +%Y%m%dT%H%M%SZ)-$(hostname 2>/dev/null || printf 'unknown')"
fi
bundle_name="$(sanitize_name "$bundle_name")"
if [[ -z "$bundle_name" ]]; then
	echo "bundle name resolved to empty value" >&2
	exit 2
fi

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd)"
bundle_dir="$out_dir/$bundle_name"
archive="$out_dir/$bundle_name.tar.gz"

if [[ -e "$bundle_dir" || -e "$archive" ]]; then
	echo "validation bundle already exists: $bundle_name" >&2
	exit 1
fi

mkdir -p "$bundle_dir/logs" "$bundle_dir/supporting"
copied_logs=()
index=0
for log in "${logs[@]}"; do
	index=$((index + 1))
	dest="$bundle_dir/logs/$(printf '%02d-%s' "$index" "$(basename "$log")")"
	cp -- "$log" "$dest"
	copied_logs+=("$dest")
done
copied_supporting=()
index=0
for file in "${supporting_files[@]}"; do
	index=$((index + 1))
	dest="$bundle_dir/supporting/$(printf '%02d-%s' "$index" "$(basename "$file")")"
	cp -- "$file" "$dest"
	copied_supporting+=("$dest")
done

runtime_guard_print_host_fingerprint >"$bundle_dir/HOST.txt"

{
	echo "created_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "bundle_name: $bundle_name"
	echo "repo_root: $repo_root"
	echo "repo_head: $(git rev-parse HEAD 2>/dev/null || printf 'unknown')"
	echo "repo_branch: $(git branch --show-current 2>/dev/null || printf 'unknown')"
	echo
	echo "repo_status:"
	git status --short --branch 2>/dev/null || true
	echo
	echo "source_logs:"
	for log in "${logs[@]}"; do
		echo "- $log"
	done
	echo
	echo "supporting_files:"
	for file in "${supporting_files[@]}"; do
		echo "- $file"
	done
} >"$bundle_dir/METADATA.txt"

set +e
scripts/validation-summary.sh "${copied_logs[@]}" >"$bundle_dir/SUMMARY.txt" 2>&1
summary_status=$?
set -e

(
	cd "$bundle_dir"
	checksum_files=(HOST.txt METADATA.txt SUMMARY.txt logs/*)
	if [[ "${#copied_supporting[@]}" -gt 0 ]]; then
		checksum_files+=(supporting/*)
	fi
	sha256sum "${checksum_files[@]}" >SHA256SUMS
)

tar -C "$out_dir" -czf "$archive" "$bundle_name"
(
	cd "$out_dir"
	sha256sum "$(basename "$archive")" >"$(basename "$archive").sha256"
)

echo "validation bundle:"
echo "$bundle_dir"
echo "$archive"
echo "$archive.sha256"
echo
cat "$bundle_dir/SUMMARY.txt"

exit "$summary_status"
