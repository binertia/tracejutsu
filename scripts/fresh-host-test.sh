#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
	cat <<'EOF'
Usage: ./test.sh [--yes] [--quick] [--duration 30m] [--package-duration 10m] [--version VERSION] [--maintainer "NAME <EMAIL>"] [--with-vuln] [--skip-deps] [--skip-go-install] [--skip-root-smoke] [--skip-release-check] [--skip-systemd-smoke] [--skip-stress] [--skip-package-smoke] [--skip-apt-repo-smoke] [--allow-container] [--dry-run]

Bootstraps and validates Tracejutsu on a fresh Debian/Ubuntu host.

The helper:
  - installs basic apt build/test dependencies
  - installs the pinned Go toolchain under ~/.local/share/tracejutsu-go if needed
  - runs the non-root release gate
  - runs root eBPF collector smoke tests
  - runs transient systemd smoke and passive stress validation
  - builds a release bundle
  - tests direct .deb installation
  - builds a local static APT repository and tests apt installation from it

This is intended for disposable fresh VPS/bare-metal validation hosts. It does
not enable Tracejutsu for boot. Package smoke runs remove the package and purge
state so the direct .deb and APT repository paths can both run on one host.
EOF
}

yes=0
dry_run=0
quick=0
with_vuln=0
skip_deps=0
skip_go_install=0
skip_root_smoke=0
skip_release_check=0
skip_systemd_smoke=0
skip_stress=0
skip_package_smoke=0
skip_apt_repo_smoke=0
allow_container=0
duration=30m
package_duration=10m
version=""
maintainer="Tracejutsu Validation <validation@example.invalid>"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--yes)
		yes=1
		shift
		;;
	--dry-run)
		dry_run=1
		shift
		;;
	--quick)
		quick=1
		duration=10m
		package_duration=2m
		shift
		;;
	--duration)
		if [[ $# -lt 2 ]]; then
			echo "--duration requires a value" >&2
			exit 2
		fi
		duration=$2
		shift 2
		;;
	--package-duration)
		if [[ $# -lt 2 ]]; then
			echo "--package-duration requires a value" >&2
			exit 2
		fi
		package_duration=$2
		shift 2
		;;
	--version)
		if [[ $# -lt 2 ]]; then
			echo "--version requires a value" >&2
			exit 2
		fi
		version=$2
		shift 2
		;;
	--maintainer)
		if [[ $# -lt 2 ]]; then
			echo "--maintainer requires a value" >&2
			exit 2
		fi
		maintainer=$2
		shift 2
		;;
	--with-vuln)
		with_vuln=1
		shift
		;;
	--skip-deps)
		skip_deps=1
		shift
		;;
	--skip-go-install)
		skip_go_install=1
		shift
		;;
	--skip-root-smoke)
		skip_root_smoke=1
		shift
		;;
	--skip-release-check)
		skip_release_check=1
		shift
		;;
	--skip-systemd-smoke)
		skip_systemd_smoke=1
		shift
		;;
	--skip-stress)
		skip_stress=1
		shift
		;;
	--skip-package-smoke)
		skip_package_smoke=1
		shift
		;;
	--skip-apt-repo-smoke)
		skip_apt_repo_smoke=1
		shift
		;;
	--allow-container)
		allow_container=1
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

root_run() {
	if [[ "$(id -u)" -eq 0 ]]; then
		"$@"
	else
		sudo "$@"
	fi
}

detect_arch() {
	case "$(uname -m)" in
	x86_64)
		printf 'amd64'
		;;
	aarch64|arm64)
		printf 'arm64'
		;;
	*)
		echo "unsupported architecture for automatic Go install: $(uname -m)" >&2
		exit 1
		;;
	esac
}

required_go_version() {
	awk '$1 == "toolchain" {sub(/^go/, "", $2); print $2; found=1} END {if (!found) exit 1}' go.mod
}

go_version_from_binary() {
	local go_bin=$1
	"$go_bin" version 2>/dev/null | awk '{sub(/^go/, "", $3); print $3}'
}

version_ge() {
	local have=$1
	local want=$2
	local hmaj hmin hpatch wmaj wmin wpatch
	IFS=. read -r hmaj hmin hpatch <<<"$have"
	IFS=. read -r wmaj wmin wpatch <<<"$want"
	hpatch=${hpatch:-0}
	wpatch=${wpatch:-0}
	[[ "$hmaj" =~ ^[0-9]+$ && "$hmin" =~ ^[0-9]+$ && "$hpatch" =~ ^[0-9]+$ ]] || return 1
	[[ "$wmaj" =~ ^[0-9]+$ && "$wmin" =~ ^[0-9]+$ && "$wpatch" =~ ^[0-9]+$ ]] || return 1
	if (( hmaj != wmaj )); then
		(( hmaj > wmaj ))
		return
	fi
	if (( hmin != wmin )); then
		(( hmin > wmin ))
		return
	fi
	(( hpatch >= wpatch ))
}

usable_go_in_path() {
	local go_bin
	local have
	if ! go_bin="$(command -v go 2>/dev/null)"; then
		return 1
	fi
	have="$(go_version_from_binary "$go_bin")"
	version_ge "$have" "$required_go"
}

ensure_go() {
	local arch
	local archive
	local install_parent
	local install_root
	local tmp
	local url
	if usable_go_in_path; then
		echo "Using Go from PATH: $(command -v go) ($(go version))"
		return
	fi
	arch="$(detect_arch)"
	archive="go${required_go}.linux-${arch}.tar.gz"
	install_parent="$HOME/.local/share/tracejutsu-go"
	install_root="$install_parent/go${required_go}"
	if [[ -x "$install_root/bin/go" ]] && version_ge "$(go_version_from_binary "$install_root/bin/go")" "$required_go"; then
		export PATH="$install_root/bin:$PATH"
		echo "Using cached Go: $install_root/bin/go ($("$install_root/bin/go" version))"
		return
	fi
	url="https://go.dev/dl/$archive"
	tmp="$(mktemp -d /tmp/tracejutsu-go.XXXXXX)"
	echo "Installing Go $required_go under $install_root"
	curl -fsSL -o "$tmp/$archive" "$url"
	mkdir -p "$install_parent"
	rm -rf -- "$install_root.tmp"
	mkdir -p "$install_root.tmp"
	tar -C "$install_root.tmp" --strip-components=1 -xzf "$tmp/$archive"
	rm -rf -- "$install_root"
	mv "$install_root.tmp" "$install_root"
	rm -rf -- "$tmp"
	export PATH="$install_root/bin:$PATH"
	go version
}

validate_host() {
	local os_id=""
	local os_like=""
	local container=""
	if [[ -r /etc/os-release ]]; then
		# shellcheck disable=SC1091
		. /etc/os-release
		os_id="${ID:-}"
		os_like="${ID_LIKE:-}"
	fi
	if [[ "$os_id $os_like" != *debian* && "$os_id $os_like" != *ubuntu* ]]; then
		echo "fresh-host test currently supports Debian/Ubuntu apt hosts only" >&2
		exit 1
	fi
	if ! command -v systemctl >/dev/null 2>&1; then
		echo "systemd is required for this validation run" >&2
		exit 1
	fi
	if command -v systemd-detect-virt >/dev/null 2>&1; then
		container="$(systemd-detect-virt --container 2>/dev/null || true)"
	fi
	if [[ "$container" == "none" ]]; then
		container=""
	fi
	if [[ -n "$container" && "$allow_container" -ne 1 ]]; then
		echo "container detected: $container" >&2
		echo "use --allow-container only if you intentionally expect systemd/eBPF validation to fail or be limited" >&2
		exit 1
	fi
}

install_deps() {
	local packages=(
		ca-certificates
		curl
		git
		build-essential
		pkg-config
		sqlite3
		sudo
	)
	root_run apt-get update
	root_run apt-get install -y "${packages[@]}"
}

run_log() {
	local name=$1
	shift
	local log="$logs_dir/$name.log"
	echo
	echo "===== $name ====="
	printf 'command:'
	printf ' %q' "$@"
	printf '\n'
	{
		printf 'command:'
		printf ' %q' "$@"
		printf '\n\n'
		"$@"
	} 2>&1 | tee "$log"
	local status=${PIPESTATUS[0]}
	if [[ "$status" -ne 0 ]]; then
		echo "step failed: $name (exit $status)" >&2
		exit "$status"
	fi
}

run_log_current_shell() {
	local name=$1
	shift
	local log="$logs_dir/$name.log"
	echo
	echo "===== $name ====="
	printf 'command:'
	printf ' %q' "$@"
	printf '\n'
	{
		printf 'command:'
		printf ' %q' "$@"
		printf '\n\n'
	} | tee "$log"
	"$@" > >(tee -a "$log") 2>&1
}

write_summary() {
	local summary="$logs_dir/SUMMARY.txt"
	local summary_logs=()
	local log
	for log in \
		"$logs_dir/systemd-smoke.log" \
		"$logs_dir/systemd-stress.log" \
		"$logs_dir/package-smoke-deb.log" \
		"$logs_dir/package-smoke-apt-repo.log"; do
		if [[ -f "$log" ]]; then
			summary_logs+=("$log")
		fi
	done
	{
		echo "Tracejutsu fresh-host validation"
		echo "repo: $repo_root"
		echo "head: $(git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)"
		echo "version: $version"
		echo "stress_duration: $duration"
		echo "package_duration: $package_duration"
		echo
		if [[ -f "$logs_dir/release-check.log" ]]; then
			echo "release_check: present"
		fi
		if [[ -f "$logs_dir/root-ebpf-smoke.log" ]]; then
			echo "root_ebpf_smoke: present"
		fi
		if [[ "${#summary_logs[@]}" -gt 0 ]]; then
			scripts/validation-summary.sh "${summary_logs[@]}" 2>/dev/null || true
		fi
	} >"$summary"
	echo
	echo "Fresh-host validation logs:"
	echo "$logs_dir"
	echo
	cat "$summary"
}

if [[ -z "$version" ]]; then
	version="0.1.0+fresh.$(date -u +%Y%m%d%H%M%S)"
fi
required_go="$(required_go_version)"
logs_dir="$repo_root/validation-artifacts/fresh-host-$(date -u +%Y%m%dT%H%M%SZ)"
release_dir="$logs_dir/release"
apt_repo_dir="$logs_dir/apt-repo"

if ! timeout "$duration" true >/dev/null 2>&1; then
	echo "invalid --duration for timeout/sleep: $duration" >&2
	exit 2
fi
if ! timeout "$package_duration" true >/dev/null 2>&1; then
	echo "invalid --package-duration for timeout/sleep: $package_duration" >&2
	exit 2
fi

validate_host

cat <<EOF
Tracejutsu fresh-host test

Will:
  - write logs under: $logs_dir
  - install apt dependencies: $([[ "$skip_deps" -eq 1 ]] && printf 'no' || printf 'yes')
  - ensure Go >= $required_go under user-local cache if needed: $([[ "$skip_go_install" -eq 1 ]] && printf 'no' || printf 'yes')
  - run release gate: $([[ "$skip_release_check" -eq 1 ]] && printf 'no' || printf 'yes')
  - run root eBPF smoke: $([[ "$skip_root_smoke" -eq 1 ]] && printf 'no' || printf 'yes')
  - run systemd smoke: $([[ "$skip_systemd_smoke" -eq 1 ]] && printf 'no' || printf 'yes')
  - run passive stress duration: $([[ "$skip_stress" -eq 1 ]] && printf 'skipped' || printf '%s' "$duration")
  - build release bundle version: $version
  - run direct .deb package smoke: $([[ "$skip_package_smoke" -eq 1 ]] && printf 'no' || printf '%s' "$package_duration")
  - run local APT repo package smoke: $([[ "$skip_apt_repo_smoke" -eq 1 ]] && printf 'no' || printf '%s' "$package_duration")

Will not:
  - enable tracejutsu.service for boot
  - leave Tracejutsu package installed after package smoke
  - publish artifacts outside this host
EOF

if [[ "$dry_run" -eq 1 ]]; then
	exit 0
fi

if [[ "$yes" -ne 1 ]]; then
	if [[ ! -t 0 ]]; then
		echo "refusing to run without --yes because stdin is not interactive" >&2
		exit 1
	fi
	read -r -p "Continue? [y/N] " answer
	case "$answer" in
	y|Y|yes|YES)
		;;
	*)
		echo "aborted"
		exit 1
		;;
	esac
fi

require_command date
require_command tee
require_command timeout
require_command uname
if [[ "$(id -u)" -ne 0 ]]; then
	require_command sudo
	sudo -v
fi

mkdir -p "$logs_dir"

if [[ "$skip_deps" -ne 1 ]]; then
	run_log install-deps install_deps
fi
require_command curl
require_command tar
if [[ "$skip_go_install" -ne 1 ]]; then
	run_log_current_shell ensure-go ensure_go
fi
require_command go
export PATH
export GOCACHE="${GOCACHE:-/tmp/tracejutsu-gocache}"
export GOMODCACHE="${GOMODCACHE:-/tmp/tracejutsu-gomodcache}"

if [[ "$skip_release_check" -ne 1 ]]; then
	if [[ "$with_vuln" -eq 1 ]]; then
		run_log release-check scripts/release-check.sh
	else
		run_log release-check scripts/release-check.sh --skip-vuln
	fi
fi

if [[ "$skip_root_smoke" -ne 1 ]]; then
	run_log root-ebpf-smoke \
		root_run env \
		"PATH=$PATH" \
		"GOCACHE=$GOCACHE" \
		"GOMODCACHE=$GOMODCACHE" \
		"$(command -v go)" test -tags=ebpf_smoke ./internal/ebpf \
		-run 'Test(Execve|Connect|FileWrite|Chmod|SensitiveRead|FileLifecycle|PrivilegeChange|NamespaceChange|ProcessAccess|NetworkServer|KernelTamper)CollectorSmoke' -v
fi

if [[ "$skip_systemd_smoke" -ne 1 ]]; then
	run_log systemd-smoke scripts/systemd-smoke.sh --yes
fi

if [[ "$skip_stress" -ne 1 ]]; then
	run_log systemd-stress scripts/systemd-stress.sh --duration "$duration" --stats-interval 1m --yes
fi

run_log release-bundle scripts/release-bundle.sh --version "$version" --out "$release_dir" --maintainer "$maintainer" --allow-dirty
deb_arch="$(dpkg --print-architecture)"
deb_path="$release_dir/tracejutsu_${version#v}_${deb_arch}.deb"
if [[ ! -f "$deb_path" ]]; then
	echo "expected release package not found: $deb_path" >&2
	exit 1
fi

if [[ "$skip_package_smoke" -ne 1 ]]; then
	run_log package-smoke-deb scripts/package-install-smoke.sh --deb "$deb_path" --version "$version" --duration "$package_duration" --purge-state --yes
fi

if [[ "$skip_apt_repo_smoke" -ne 1 ]]; then
	run_log build-apt-repo scripts/build-apt-repo.sh --deb "$deb_path" --out "$apt_repo_dir"
	run_log package-smoke-apt-repo scripts/package-install-smoke.sh --apt-repo "$apt_repo_dir" --apt-trusted --version "$version" --duration "$package_duration" --purge-state --yes
fi

write_summary
