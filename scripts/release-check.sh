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

verify_tar_artifact() {
	local out_dir=$1
	local version=$2
	local name="runtime-guard-${version}-linux-amd64"
	local extract_dir="$artifact_check_dir/tar-extract"
	run bash -c "cd \"\$1\" && sha256sum -c \"\$2.tar.gz.sha256\" && sha256sum -c SHA256SUMS" _ "$out_dir" "$name"
	mkdir -p "$extract_dir"
	tar -C "$extract_dir" -xzf "$out_dir/$name.tar.gz"
	run "$extract_dir/$name/runtime-guard" version
	"$extract_dir/$name/runtime-guard" version | grep -F "runtime-guard $version" >/dev/null
	grep -F "ExecStart=/usr/local/bin/runtime-guard" "$extract_dir/$name/packaging/systemd/runtime-guard.service" >/dev/null
}

verify_deb_artifact() {
	local out_dir=$1
	local version=$2
	local maintainer=${3:-}
	local name="runtime-guard_${version}_amd64"
	local extract_dir="$artifact_check_dir/deb-extract"
	local package_info
	run bash -c "cd \"\$1\" && sha256sum -c \"\$2.deb.sha256\"" _ "$out_dir" "$name"
	package_info="$(dpkg-deb --info "$out_dir/$name.deb")"
	printf '%s\n' "$package_info" | grep -F "Version: $version" >/dev/null
	if [[ -n "$maintainer" ]]; then
		printf '%s\n' "$package_info" | grep -F "Maintainer: $maintainer" >/dev/null
	fi
	dpkg-deb --contents "$out_dir/$name.deb" | grep -F "./usr/bin/runtime-guard" >/dev/null
	mkdir -p "$extract_dir"
	dpkg-deb -x "$out_dir/$name.deb" "$extract_dir"
	run "$extract_dir/usr/bin/runtime-guard" version
	"$extract_dir/usr/bin/runtime-guard" version | grep -F "runtime-guard $version" >/dev/null
	grep -F "ExecStart=/usr/bin/runtime-guard" "$extract_dir/lib/systemd/system/runtime-guard.service" >/dev/null
}

require_command bash
require_command git
require_command go
require_command grep
require_command mktemp
require_command sha256sum
require_command tar

export GOCACHE="${GOCACHE:-/tmp/runtime-guard-gocache}"
export GOMODCACHE="${GOMODCACHE:-/tmp/runtime-guard-gomodcache}"
artifact_check_dir="$(mktemp -d)"
trap 'rm -rf "$artifact_check_dir"' EXIT
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1780531200}"

run go version
run git diff --check
run git diff --cached --check
run bash -n \
	scripts/dependency-review.sh \
	scripts/release-check.sh \
	scripts/build-release.sh \
	scripts/build-deb.sh \
	scripts/release-manifest.sh \
	scripts/package-install-smoke.sh \
	scripts/container-workload.sh \
	scripts/systemd-helper-lib.sh \
	scripts/systemd-smoke.sh \
	scripts/systemd-stress.sh \
	scripts/validation-bundle.sh \
	scripts/validation-summary.sh
run go test ./...
run go vet ./...
run go test -race ./...
run go test -tags=ebpf_smoke ./internal/ebpf -run '^$'
release_dir="$artifact_check_dir/release"
check_version=0.0.0-check
run scripts/build-release.sh --version "$check_version" --out "$release_dir"
verify_tar_artifact "$release_dir" "$check_version"
if command -v dpkg-deb >/dev/null 2>&1; then
	check_maintainer="Runtime Guard Check <check@example.invalid>"
	run scripts/build-deb.sh --version "$check_version" --out "$release_dir" --maintainer "$check_maintainer"
	verify_deb_artifact "$release_dir" "$check_version" "$check_maintainer"
else
	echo
	echo "===== Debian package build skipped: dpkg-deb unavailable ====="
fi
run scripts/release-manifest.sh --dir "$release_dir"
run scripts/release-manifest.sh --dir "$release_dir" --verify

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
