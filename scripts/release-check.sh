#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
	cat <<'EOF'
Usage: scripts/release-check.sh [--skip-vuln]

Runs the non-root release gate used before publishing or packaging Tracejutsu.
It does not run live eBPF smoke tests, systemd helpers, or any command
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
	local name="tracejutsu-${version}-linux-amd64"
	local extract_dir="$artifact_check_dir/tar-extract"
	run bash -c "cd \"\$1\" && sha256sum -c \"\$2.tar.gz.sha256\" && sha256sum -c SHA256SUMS" _ "$out_dir" "$name"
	mkdir -p "$extract_dir"
	tar -C "$extract_dir" -xzf "$out_dir/$name.tar.gz"
	run "$extract_dir/$name/tracejutsu" version
	"$extract_dir/$name/tracejutsu" version | grep -F "tracejutsu $version" >/dev/null
	grep -F "ExecStart=/usr/local/bin/tracejutsu" "$extract_dir/$name/packaging/systemd/tracejutsu.service" >/dev/null
}

verify_deb_artifact() {
	local out_dir=$1
	local version=$2
	local maintainer=${3:-}
	local name="tracejutsu_${version}_amd64"
	local extract_dir="$artifact_check_dir/deb-extract"
	local package_info
	run bash -c "cd \"\$1\" && sha256sum -c \"\$2.deb.sha256\"" _ "$out_dir" "$name"
	package_info="$(dpkg-deb --info "$out_dir/$name.deb")"
	printf '%s\n' "$package_info" | grep -F "Version: $version" >/dev/null
	if [[ -n "$maintainer" ]]; then
		printf '%s\n' "$package_info" | grep -F "Maintainer: $maintainer" >/dev/null
	fi
	dpkg-deb --contents "$out_dir/$name.deb" | grep -F "./usr/bin/tracejutsu" >/dev/null
	mkdir -p "$extract_dir"
	dpkg-deb -x "$out_dir/$name.deb" "$extract_dir"
	run "$extract_dir/usr/bin/tracejutsu" version
	"$extract_dir/usr/bin/tracejutsu" version | grep -F "tracejutsu $version" >/dev/null
	grep -F "ExecStart=/usr/bin/tracejutsu" "$extract_dir/lib/systemd/system/tracejutsu.service" >/dev/null
}

verify_rpm_artifact() {
	local out_dir=$1
	local version=$2
	local packager=${3:-}
	local name="tracejutsu-${version}-1.x86_64"
	local package_query
	run bash -c "cd \"\$1\" && sha256sum -c \"\$2.rpm.sha256\"" _ "$out_dir" "$name"
	if command -v rpm >/dev/null 2>&1; then
		package_query="$(rpm -qp --qf '%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n%{PACKAGER}\n' "$out_dir/$name.rpm")"
		printf '%s\n' "$package_query" | grep -Fx "tracejutsu" >/dev/null
		printf '%s\n' "$package_query" | grep -Fx "$version" >/dev/null
		printf '%s\n' "$package_query" | grep -Fx "1" >/dev/null
		printf '%s\n' "$package_query" | grep -Fx "x86_64" >/dev/null
		if [[ -n "$packager" ]]; then
			printf '%s\n' "$package_query" | grep -Fx "$packager" >/dev/null
		fi
		rpm -qpl "$out_dir/$name.rpm" | grep -Fx "/usr/bin/tracejutsu" >/dev/null
		rpm -qpl "$out_dir/$name.rpm" | grep -Fx "/lib/systemd/system/tracejutsu.service" >/dev/null
	else
		echo "RPM metadata verification skipped: rpm unavailable"
	fi
}

verify_apt_repo() {
	local repo_dir=$1
	local suite=$2
	local version=$3
	local packages_file="$repo_dir/dists/$suite/main/binary-amd64/Packages"
	local release_file="$repo_dir/dists/$suite/Release"
	grep -F "Package: tracejutsu" "$packages_file" >/dev/null
	grep -F "Version: $version" "$packages_file" >/dev/null
	grep -F "Filename: pool/main/t/tracejutsu/tracejutsu_${version}_amd64.deb" "$packages_file" >/dev/null
	gzip -t "$packages_file.gz"
	grep -F "Architectures: amd64" "$release_file" >/dev/null
	grep -F "Components: main" "$release_file" >/dev/null
	grep -F "SHA256:" "$release_file" >/dev/null
	grep -F "main/binary-amd64/Packages" "$release_file" >/dev/null
	grep -F "main/binary-amd64/Packages.gz" "$release_file" >/dev/null
}

require_command bash
require_command git
require_command go
require_command grep
require_command gzip
require_command mktemp
require_command sha256sum
require_command tar

export GOCACHE="${GOCACHE:-/tmp/tracejutsu-gocache}"
export GOMODCACHE="${GOMODCACHE:-/tmp/tracejutsu-gomodcache}"
artifact_check_dir="$(mktemp -d)"
trap 'rm -rf "$artifact_check_dir"' EXIT
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1780531200}"

run go version
run git diff --check
run git diff --cached --check
run bash -n \
	test.sh \
	scripts/dependency-review.sh \
	scripts/release-check.sh \
	scripts/build-release.sh \
	scripts/build-deb.sh \
	scripts/build-rpm.sh \
	scripts/build-apt-repo.sh \
	scripts/fresh-host-test.sh \
	scripts/release-bundle.sh \
	scripts/release-manifest.sh \
	scripts/package-install-smoke.sh \
	scripts/rpm-install-smoke.sh \
	scripts/ops-validation.sh \
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
bundle_dir="$artifact_check_dir/bundle"
apt_repo_dir="$artifact_check_dir/apt-repo"
check_version=0.0.0-check
run scripts/build-release.sh --version "$check_version" --out "$release_dir"
verify_tar_artifact "$release_dir" "$check_version"
if command -v dpkg-deb >/dev/null 2>&1; then
	check_maintainer="Tracejutsu Check <check@example.invalid>"
	run scripts/build-deb.sh --version "$check_version" --out "$release_dir" --maintainer "$check_maintainer"
	verify_deb_artifact "$release_dir" "$check_version" "$check_maintainer"
	run scripts/build-apt-repo.sh --deb "$release_dir/tracejutsu_${check_version}_amd64.deb" --out "$apt_repo_dir"
	verify_apt_repo "$apt_repo_dir" stable "$check_version"
else
	echo
	echo "===== Debian package build skipped: dpkg-deb unavailable ====="
fi
bundle_args=(--version "$check_version" --out "$bundle_dir" --skip-dependency-review --allow-dirty)
if command -v dpkg-deb >/dev/null 2>&1; then
	bundle_args+=(--maintainer "$check_maintainer")
else
	bundle_args+=(--skip-deb)
fi
run scripts/release-bundle.sh "${bundle_args[@]}"
if command -v rpmbuild >/dev/null 2>&1; then
	check_packager="Tracejutsu Check <check@example.invalid>"
	rpm_check_version="${check_version//-/.}"
	run scripts/build-rpm.sh --version "$rpm_check_version" --out "$release_dir" --packager "$check_packager"
	verify_rpm_artifact "$release_dir" "$rpm_check_version" "$check_packager"
else
	echo
	echo "===== RPM package build skipped: rpmbuild unavailable ====="
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

run scripts/dependency-review.sh --out /tmp/tracejutsu-dependency-review.md

echo
echo "release check passed"
