#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: scripts/rpm-install-smoke.sh [--rpm PATH] [--duration 2m] [--version VERSION] [--release RELEASE] [--allow-existing-state] [--keep-installed] [--purge-state] [--yes]

Builds a temporary RPM package, or uses an existing package supplied with
--rpm, installs it, verifies that the package does not enable or start
tracejutsu.service automatically, starts the packaged service briefly, validates
the final runtime drop counters, stops the service, and removes the package
again.

This helper is intended for disposable or fresh Fedora/RHEL-compatible
validation hosts. It refuses to run when a Tracejutsu package, service unit,
binary, or state directory already exists unless the relevant override is
supplied.

Options:
  --rpm PATH                 Install and validate an existing tracejutsu RPM
                             instead of building a temporary package.
  --duration DURATION        How long to run the installed service. Default: 2m.
  --version VERSION          Package version to build. Default is a unique
                             0.0.0.install.smoke.TIMESTAMP.PID value. With
                             --rpm, verifies the package version if supplied.
  --release RELEASE          RPM release to build. Default: 1. With --rpm,
                             verifies the package release if supplied.
  --allow-existing-state     Allow an existing /var/lib/tracejutsu directory.
  --keep-installed           Leave the package installed after validation.
  --purge-state              Remove /var/lib/tracejutsu after validation.
  --yes                      Skip the interactive confirmation prompt.
  --help                     Show this help.
EOF
}

duration=2m
version=""
rpm_release=""
rpm_release_supplied=0
rpm_path_input=""
allow_existing_state=0
keep_installed=0
purge_state=0
assume_yes=0
packager="${TRACEJUTSU_PACKAGE_MAINTAINER:-Tracejutsu Maintainers <maintainers@example.invalid>}"
license="${TRACEJUTSU_PACKAGE_LICENSE:-LicenseRef-Private}"
invoke_cwd="$(pwd)"

while [[ $# -gt 0 ]]; do
	case "$1" in
	--rpm)
		if [[ $# -lt 2 ]]; then
			echo "--rpm requires a value" >&2
			exit 2
		fi
		rpm_path_input=$2
		shift 2
		;;
	--duration)
		if [[ $# -lt 2 ]]; then
			echo "--duration requires a value" >&2
			exit 2
		fi
		duration=$2
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
	--release)
		if [[ $# -lt 2 ]]; then
			echo "--release requires a value" >&2
			exit 2
		fi
		rpm_release=$2
		rpm_release_supplied=1
		shift 2
		;;
	--allow-existing-state)
		allow_existing_state=1
		shift
		;;
	--keep-installed)
		keep_installed=1
		shift
		;;
	--purge-state)
		purge_state=1
		shift
		;;
	--yes)
		assume_yes=1
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

tracejutsu_package_installed() {
	rpm -q tracejutsu >/dev/null 2>&1
}

absolute_existing_file() {
	local path=$1
	local dir
	local base
	if [[ "$path" != /* ]]; then
		path="$invoke_cwd/$path"
	fi
	if [[ ! -f "$path" || ! -r "$path" ]]; then
		echo "file is not readable: $path" >&2
		exit 1
	fi
	dir="$(cd "$(dirname "$path")" && pwd)"
	base="$(basename "$path")"
	printf '%s/%s\n' "$dir" "$base"
}

rpm_field() {
	local rpm_path=$1
	local field=$2
	local value
	value="$(rpm -qp --qf "%{$field}" "$rpm_path")" || {
		echo "failed to read RPM field $field from $rpm_path" >&2
		exit 1
	}
	if [[ -z "$value" || "$value" == "(none)" ]]; then
		echo "RPM field $field is empty in $rpm_path" >&2
		exit 1
	fi
	printf '%s\n' "$value"
}

verify_tracejutsu_rpm_metadata() {
	local rpm_path=$1
	local package_name
	local package_version
	local package_release
	local package_arch
	local host_arch
	package_name="$(rpm_field "$rpm_path" NAME)"
	package_version="$(rpm_field "$rpm_path" VERSION)"
	package_release="$(rpm_field "$rpm_path" RELEASE)"
	package_arch="$(rpm_field "$rpm_path" ARCH)"
	host_arch="$(rpm --eval '%{_arch}')"

	if [[ "$package_name" != tracejutsu ]]; then
		echo "RPM package name is $package_name, expected tracejutsu" >&2
		exit 1
	fi
	if [[ "$package_arch" != "$host_arch" && "$package_arch" != noarch ]]; then
		echo "RPM package architecture is $package_arch, host architecture is $host_arch" >&2
		exit 1
	fi
	if [[ -n "$version" && "$package_version" != "$version" && "$package_version" != "${version#v}" ]]; then
		echo "RPM package version is $package_version, expected $version" >&2
		exit 1
	fi
	if [[ "$rpm_release_supplied" -eq 1 && "$package_release" != "$rpm_release" ]]; then
		echo "RPM package release is $package_release, expected $rpm_release" >&2
		exit 1
	fi
	if [[ -z "$version" ]]; then
		version="$package_version"
	fi
	if [[ -z "$rpm_release" ]]; then
		rpm_release="$package_release"
	fi

	rpm_package_version="$package_version"
	rpm_package_release="$package_release"
	rpm_package_arch="$package_arch"
}

verify_rpm_checksum_if_present() {
	local rpm_path=$1
	local checksum_file="$rpm_path.sha256"
	if [[ -r "$checksum_file" ]]; then
		(
			cd "$(dirname "$rpm_path")"
			sha256sum -c "$(basename "$checksum_file")"
		)
	else
		echo "checksum file not found for $rpm_path; skipping checksum verification" >&2
	fi
}

journal_since_timestamp() {
	date '+%Y-%m-%d %H:%M:%S'
}

refuse_existing_tracejutsu() {
	local found=0
	local path
	if tracejutsu_package_installed; then
		echo "existing tracejutsu package is installed" >&2
		found=1
	fi
	for path in \
		/etc/systemd/system/tracejutsu.service \
		/lib/systemd/system/tracejutsu.service \
		/usr/lib/systemd/system/tracejutsu.service \
		/usr/bin/tracejutsu \
		/usr/local/bin/tracejutsu; do
		if [[ -e "$path" || -L "$path" ]]; then
			echo "existing Tracejutsu path found: $path" >&2
			found=1
		fi
	done
	if [[ "$allow_existing_state" -ne 1 && ( -e "$state_dir" || -L "$state_dir" ) ]]; then
		echo "existing Tracejutsu state directory found: $state_dir" >&2
		echo "use --allow-existing-state only when this state belongs to this validation run" >&2
		found=1
	fi
	if [[ "$found" -ne 0 ]]; then
		echo "refusing RPM install smoke on a non-fresh target" >&2
		exit 1
	fi
}

stop_service_if_started() {
	if [[ "$started_service" -eq 1 ]]; then
		sudo systemctl stop tracejutsu.service >/dev/null 2>&1 || true
		started_service=0
	fi
}

start_sudo_keepalive() {
	(
		while true; do
			sleep 60
			sudo -n true >/dev/null 2>&1 || exit 0
		done
	) &
	sudo_keepalive_pid=$!
}

stop_sudo_keepalive() {
	if [[ -n "${sudo_keepalive_pid:-}" ]]; then
		kill "$sudo_keepalive_pid" >/dev/null 2>&1 || true
		wait "$sudo_keepalive_pid" >/dev/null 2>&1 || true
		sudo_keepalive_pid=""
	fi
}

install_rpm_package() {
	local rpm_path=$1
	if command -v dnf >/dev/null 2>&1; then
		sudo dnf install -y "$rpm_path"
		return
	fi
	if command -v yum >/dev/null 2>&1; then
		sudo yum install -y "$rpm_path"
		return
	fi
	sudo rpm -Uvh "$rpm_path"
}

remove_package_if_installed() {
	if [[ "$installed_package" -eq 1 && "$keep_installed" -ne 1 ]]; then
		sudo rpm -e tracejutsu || true
		sudo systemctl daemon-reload || true
		installed_package=0
	fi
}

cleanup() {
	local status=$?
	trap - EXIT INT TERM HUP
	stop_service_if_started
	remove_package_if_installed
	if [[ "$purge_state" -eq 1 ]]; then
		sudo rm -rf -- "$state_dir" >/dev/null 2>&1 || true
	fi
	stop_sudo_keepalive
	if [[ -n "${tmp_dir:-}" && "$tmp_dir" == /tmp/tracejutsu-rpm-install.* ]]; then
		rm -rf -- "$tmp_dir"
	fi
	exit "$status"
}

require_command bash
require_command date
require_command find
require_command flock
require_command grep
require_command journalctl
require_command mktemp
require_command rpm
require_command sha256sum
require_command sudo
require_command systemctl
require_command timeout

if ! timeout "$duration" true >/dev/null 2>&1; then
	echo "invalid --duration for timeout/sleep: $duration" >&2
	exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
source "$repo_root/scripts/systemd-helper-lib.sh"

lock_file=/tmp/tracejutsu-systemd-helper.lock
exec 9>"$lock_file"
if ! flock -n 9; then
	echo "another Tracejutsu systemd smoke/stress/install helper is already running" >&2
	echo "wait for it to finish before starting a new helper run" >&2
	exit 1
fi

run_id="$(date +%Y%m%d%H%M%S)-$$"
state_dir=/var/lib/tracejutsu
use_existing_rpm=0
rpm_path=""
rpm_package_version=""
rpm_package_release=""
rpm_package_arch=""
if [[ -n "$rpm_path_input" ]]; then
	use_existing_rpm=1
	rpm_path="$(absolute_existing_file "$rpm_path_input")"
	verify_tracejutsu_rpm_metadata "$rpm_path"
else
	if [[ -z "$version" ]]; then
		version="0.0.0.install.smoke.$(date +%Y%m%d%H%M%S).$$"
	fi
	if [[ -z "$rpm_release" ]]; then
		rpm_release=1
	fi
fi

started_service=0
installed_package=0
sudo_keepalive_pid=""
tmp_dir=""

refuse_existing_tracejutsu

cat <<EOF
Tracejutsu RPM install smoke test

Will:
EOF
if [[ "$use_existing_rpm" -eq 1 ]]; then
	cat <<EOF
  - use RPM package: $rpm_path
  - package version: $rpm_package_version
  - package release: $rpm_package_release
  - package architecture: $rpm_package_arch
EOF
else
	cat <<EOF
  - build a temporary RPM package version: $version
  - build a temporary RPM package release: $rpm_release
EOF
fi
cat <<EOF
  - install package: tracejutsu
  - verify the package does not auto-enable or auto-start the service
  - start packaged service: tracejutsu.service
  - run duration: $duration
  - validate final runtime drop counters
  - stop packaged service
  - remove package after validation: $([[ "$keep_installed" -eq 1 ]] && printf 'no' || printf 'yes')
  - leave state for inspection: $([[ "$purge_state" -eq 1 ]] && printf 'no' || printf 'yes')

Will not:
  - run if an existing Tracejutsu install is detected
  - enable the service for boot
  - remove /var/lib/tracejutsu unless --purge-state is supplied
EOF
tracejutsu_print_host_fingerprint

if [[ "$assume_yes" -ne 1 ]]; then
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

tracejutsu_require_sudo_access
start_sudo_keepalive
trap cleanup EXIT INT TERM HUP

tmp_dir="$(mktemp -d /tmp/tracejutsu-rpm-install.XXXXXX)"
rpm_out="$tmp_dir/rpm"

if [[ "$use_existing_rpm" -eq 1 ]]; then
	verify_rpm_checksum_if_present "$rpm_path"
else
	scripts/build-rpm.sh --version "$version" --release "$rpm_release" --out "$rpm_out" --packager "$packager" --license "$license"
	rpm_path="$(find "$rpm_out" -maxdepth 1 -type f -name 'tracejutsu-*.rpm' -print -quit)"
	if [[ -z "$rpm_path" ]]; then
		echo "built RPM not found in $rpm_out" >&2
		exit 1
	fi
	verify_tracejutsu_rpm_metadata "$rpm_path"
	verify_rpm_checksum_if_present "$rpm_path"
fi

echo
echo "===== installing package ====="
install_rpm_package "$rpm_path"
installed_package=1
sudo systemctl daemon-reload

echo
echo "===== installed binary ====="
installed_version_output="$(/usr/bin/tracejutsu version)"
printf '%s\n' "$installed_version_output"
expected_version_line="tracejutsu $version"
alternate_version_line=""
if [[ "$version" == v* ]]; then
	alternate_version_line="tracejutsu ${version#v}"
else
	alternate_version_line="tracejutsu v$version"
fi
if ! printf '%s\n' "$installed_version_output" | grep -F "$expected_version_line" >/dev/null &&
	! printf '%s\n' "$installed_version_output" | grep -F "$alternate_version_line" >/dev/null; then
	echo "installed binary version did not match package version $version" >&2
	exit 1
fi
systemctl cat tracejutsu.service | grep -F "ExecStart=/usr/bin/tracejutsu" >/dev/null

if sudo systemctl is-active --quiet tracejutsu.service; then
	echo "package unexpectedly started tracejutsu.service" >&2
	exit 1
fi
if sudo systemctl is-enabled --quiet tracejutsu.service; then
	echo "package unexpectedly enabled tracejutsu.service" >&2
	exit 1
fi

journal_since="$(journal_since_timestamp)"

echo
echo "===== starting packaged service ====="
sudo systemctl start tracejutsu.service
started_service=1
sleep 5
sudo systemctl is-active --quiet tracejutsu.service

/bin/true || true
sudo sh -c 'set -eu; printf "tracejutsu rpm smoke\n" > /var/lib/tracejutsu/rpm-smoke-file; chmod +x /var/lib/tracejutsu/rpm-smoke-file'
if command -v bash >/dev/null 2>&1; then
	if command -v timeout >/dev/null 2>&1; then
		timeout 1s bash -c "</dev/tcp/127.0.0.1/1" 2>/dev/null || true
	else
		bash -c "</dev/tcp/127.0.0.1/1" 2>/dev/null || true
	fi
fi

sleep "$duration"
run_status=0
if ! sudo systemctl is-active --quiet tracejutsu.service; then
	echo "tracejutsu.service stopped before validation completed" >&2
	run_status=1
else
	sudo systemctl stop tracejutsu.service
	started_service=0
	sleep 2
fi

echo
echo "===== systemctl status tracejutsu.service ====="
status_output="$(sudo systemctl status tracejutsu.service --no-pager 2>&1)" || status_status=$?
printf '%s\n' "$status_output"

echo
echo "===== journalctl -u tracejutsu.service ====="
journal_output="$(sudo journalctl -u tracejutsu.service --since "$journal_since" --no-pager 2>&1)" || journal_status=$?
if [[ "${journal_status:-0}" -ne 0 ]]; then
	printf '%s\n' "$journal_output"
	echo "journalctl --since failed; retrying without --since" >&2
	journal_output="$(sudo journalctl -u tracejutsu.service --no-pager 2>&1)" || journal_status=$?
fi
printf '%s\n' "$journal_output"

tracejutsu_print_validation_summary "$run_status" "" "$journal_output"
final_stats="$(tracejutsu_final_runtime_stats "$journal_output")"
set +e
tracejutsu_validation_exit_status "$run_status" "$final_stats"
validation_status=$?
set -e

echo
if [[ "$keep_installed" -eq 1 ]]; then
	echo "Package left installed by request."
else
	echo "Removing package tracejutsu."
	remove_package_if_installed
fi

if [[ "$purge_state" -eq 1 ]]; then
	echo "Removing state directory: $state_dir"
	sudo rm -rf -- "$state_dir"
else
	echo "State directory left for inspection: $state_dir"
	echo "Useful inspection commands:"
	echo "  sudo du -h '$state_dir'"
	if [[ "$keep_installed" -eq 1 ]]; then
		echo "  sudo /usr/bin/tracejutsu db-stats --db '$state_dir/tracejutsu.db'"
		echo "  sudo /usr/bin/tracejutsu event-summary --db '$state_dir/tracejutsu.db' --type file_write --limit 10"
	else
		echo "  rerun with --keep-installed or use a repo-built tracejutsu binary for CLI inspection"
	fi
	echo "Cleanup command after inspection:"
	echo "  sudo rm -rf -- '$state_dir'"
fi

exit "$validation_status"
