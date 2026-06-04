#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
	cat <<'EOF'
Usage: scripts/release-check.sh [--skip-vuln]

Runs the non-root release gate used before publishing or packaging Runtime
Guard. It does not run live eBPF smoke tests, systemd helpers, or any command
that needs sudo.

Options:
  --skip-vuln  Skip govulncheck. Use only when network/tooling is unavailable.
  --help       Show this help.
EOF
}

skip_vuln=0
while [[ $# -gt 0 ]]; do
	case "$1" in
	--skip-vuln)
		skip_vuln=1
		shift
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

run() {
	printf '\n===== %s =====\n' "$*"
	"$@"
}

require_command bash
require_command git
require_command go

export GOCACHE="${GOCACHE:-/tmp/runtime-guard-gocache}"
export GOMODCACHE="${GOMODCACHE:-/tmp/runtime-guard-gomodcache}"

run go version
run git diff --check
run git diff --cached --check
run bash -n \
	scripts/dependency-review.sh \
	scripts/release-check.sh \
	scripts/build-release.sh \
	scripts/systemd-helper-lib.sh \
	scripts/systemd-smoke.sh \
	scripts/systemd-stress.sh \
	scripts/validation-summary.sh
run go test ./...
run go vet ./...
run go test -race ./...
run go test -tags=ebpf_smoke ./internal/ebpf -run '^$'

if [[ "$skip_vuln" -eq 0 ]]; then
	if command -v govulncheck >/dev/null 2>&1; then
		run govulncheck ./...
	else
		run go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	fi
else
	echo
	echo "===== govulncheck skipped ====="
fi

run scripts/dependency-review.sh --out /tmp/runtime-guard-dependency-review.md

echo
echo "release check passed"
