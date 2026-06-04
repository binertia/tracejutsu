#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: scripts/package-install-smoke.sh [--duration 2m] [--version VERSION] [--allow-existing-state] [--keep-installed] [--purge-state] [--yes]

Builds a temporary Debian package, installs it, verifies that the package does
not enable or start runtime-guard.service automatically, starts the packaged
service briefly, validates the final runtime drop counters, stops the service,
and removes the package again.

This helper is intended for disposable or fresh Debian/Ubuntu validation hosts.
It refuses to run when a Runtime Guard package, service unit, binary, or state
directory already exists unless the relevant override is supplied.

Options:
  --duration DURATION        How long to run the installed service. Default: 2m.
  --version VERSION          Package version to build. Default is a unique
                             0.0.0+install.smoke.TIMESTAMP.PID value.
  --allow-existing-state     Allow an existing /var/lib/runtime-guard directory.
  --keep-installed           Leave the package installed after validation.
  --purge-state              Remove /var/lib/runtime-guard after validation.
  --yes                      Skip the interactive confirmation prompt.
  --help                     Show this help.
EOF
}

duration=2m
version=""
allow_existing_state=0
keep_installed=0
purge_state=0
assume_yes=0

while [[ $# -gt 0 ]]; do
	case "$1" in
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

runtime_guard_package_installed() {
	local status
	status="$(dpkg-query -W -f='${db:Status-Abbrev}' runtime-guard 2>/dev/null || true)"
	[[ "$status" == ii* ]]
}

journal_since_timestamp() {
	date '+%Y-%m-%d %H:%M:%S'
}

refuse_existing_runtime_guard() {
	local found=0
	local path
	if runtime_guard_package_installed; then
		echo "existing runtime-guard package is installed" >&2
		found=1
	fi
	for path in \
		/etc/systemd/system/runtime-guard.service \
		/lib/systemd/system/runtime-guard.service \
		/usr/lib/systemd/system/runtime-guard.service \
		/usr/bin/runtime-guard \
		/usr/local/bin/runtime-guard; do
		if [[ -e "$path" || -L "$path" ]]; then
			echo "existing Runtime Guard path found: $path" >&2
			found=1
		fi
	done
	if [[ "$allow_existing_state" -ne 1 && ( -e "$state_dir" || -L "$state_dir" ) ]]; then
		echo "existing Runtime Guard state directory found: $state_dir" >&2
		echo "use --allow-existing-state only when this state belongs to this validation run" >&2
		found=1
	fi
	if [[ "$found" -ne 0 ]]; then
		echo "refusing package install smoke on a non-fresh target" >&2
		exit 1
	fi
}

stop_service_if_started() {
	if [[ "$started_service" -eq 1 ]]; then
		sudo systemctl stop runtime-guard.service >/dev/null 2>&1 || true
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

remove_package_if_installed() {
	if [[ "$installed_package" -eq 1 && "$keep_installed" -ne 1 ]]; then
		if ! sudo dpkg -r runtime-guard; then
			echo "normal package removal failed; attempting forced purge cleanup" >&2
			sudo dpkg --purge --force-remove-reinstreq runtime-guard || true
		fi
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
	if [[ -n "${tmp_dir:-}" && "$tmp_dir" == /tmp/runtime-guard-package-install.* ]]; then
		rm -rf -- "$tmp_dir"
	fi
	exit "$status"
}

require_command bash
require_command date
require_command dpkg
require_command dpkg-query
require_command find
require_command flock
require_command grep
require_command journalctl
require_command mktemp
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

lock_file=/tmp/runtime-guard-systemd-helper.lock
exec 9>"$lock_file"
if ! flock -n 9; then
	echo "another Runtime Guard systemd smoke/stress/install helper is already running" >&2
	echo "wait for it to finish before starting a new helper run" >&2
	exit 1
fi

run_id="$(date +%Y%m%d%H%M%S)-$$"
state_dir=/var/lib/runtime-guard
if [[ -z "$version" ]]; then
	version="0.0.0+install.smoke.$(date +%Y%m%d%H%M%S).$$"
fi

started_service=0
installed_package=0
sudo_keepalive_pid=""
tmp_dir=""

refuse_existing_runtime_guard

cat <<EOF
Runtime Guard package install smoke test

Will:
  - build a temporary Debian package version: $version
  - install package: runtime-guard
  - verify the package does not auto-enable or auto-start the service
  - start packaged service: runtime-guard.service
  - run duration: $duration
  - validate final runtime drop counters
  - stop packaged service
  - remove package after validation: $([[ "$keep_installed" -eq 1 ]] && printf 'no' || printf 'yes')
  - leave state for inspection: $([[ "$purge_state" -eq 1 ]] && printf 'no' || printf 'yes')

Will not:
  - run if an existing Runtime Guard install is detected
  - enable the service for boot
  - remove /var/lib/runtime-guard unless --purge-state is supplied
EOF
runtime_guard_print_host_fingerprint

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

runtime_guard_require_sudo_access
start_sudo_keepalive
trap cleanup EXIT INT TERM HUP

tmp_dir="$(mktemp -d /tmp/runtime-guard-package-install.XXXXXX)"
deb_out="$tmp_dir/deb"

scripts/build-deb.sh --version "$version" --out "$deb_out"
deb_path="$(find "$deb_out" -maxdepth 1 -type f -name 'runtime-guard_*.deb' -print -quit)"
if [[ -z "$deb_path" ]]; then
	echo "built package not found in $deb_out" >&2
	exit 1
fi
(
	cd "$(dirname "$deb_path")"
	sha256sum -c "$(basename "$deb_path").sha256"
)

echo
echo "===== installing package ====="
sudo dpkg -i "$deb_path"
installed_package=1
sudo systemctl daemon-reload

echo
echo "===== installed binary ====="
/usr/bin/runtime-guard version
/usr/bin/runtime-guard version | grep -F "runtime-guard $version" >/dev/null
systemctl cat runtime-guard.service | grep -F "ExecStart=/usr/bin/runtime-guard" >/dev/null

if sudo systemctl is-active --quiet runtime-guard.service; then
	echo "package unexpectedly started runtime-guard.service" >&2
	exit 1
fi
if sudo systemctl is-enabled --quiet runtime-guard.service; then
	echo "package unexpectedly enabled runtime-guard.service" >&2
	exit 1
fi

journal_since="$(journal_since_timestamp)"

echo
echo "===== starting packaged service ====="
sudo systemctl start runtime-guard.service
started_service=1
sleep 5
sudo systemctl is-active --quiet runtime-guard.service

/bin/true || true
sudo sh -c 'set -eu; printf "runtime-guard package smoke\n" > /var/lib/runtime-guard/package-smoke-file; chmod +x /var/lib/runtime-guard/package-smoke-file'
if command -v bash >/dev/null 2>&1; then
	if command -v timeout >/dev/null 2>&1; then
		timeout 1s bash -c "</dev/tcp/127.0.0.1/1" 2>/dev/null || true
	else
		bash -c "</dev/tcp/127.0.0.1/1" 2>/dev/null || true
	fi
fi

sleep "$duration"
run_status=0
if ! sudo systemctl is-active --quiet runtime-guard.service; then
	echo "runtime-guard.service stopped before validation completed" >&2
	run_status=1
else
	sudo systemctl stop runtime-guard.service
	started_service=0
	sleep 2
fi

echo
echo "===== systemctl status runtime-guard.service ====="
status_output="$(sudo systemctl status runtime-guard.service --no-pager 2>&1)" || status_status=$?
printf '%s\n' "$status_output"

echo
echo "===== journalctl -u runtime-guard.service ====="
journal_output="$(sudo journalctl -u runtime-guard.service --since "$journal_since" --no-pager 2>&1)" || journal_status=$?
if [[ "${journal_status:-0}" -ne 0 ]]; then
	printf '%s\n' "$journal_output"
	echo "journalctl --since failed; retrying without --since" >&2
	journal_output="$(sudo journalctl -u runtime-guard.service --no-pager 2>&1)" || journal_status=$?
fi
printf '%s\n' "$journal_output"

runtime_guard_print_validation_summary "$run_status" "" "$journal_output"
final_stats="$(runtime_guard_final_runtime_stats "$journal_output")"
set +e
runtime_guard_validation_exit_status "$run_status" "$final_stats"
validation_status=$?
set -e

echo
if [[ "$keep_installed" -eq 1 ]]; then
	echo "Package left installed by request."
else
	echo "Removing package runtime-guard."
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
		echo "  sudo /usr/bin/runtime-guard db-stats --db '$state_dir/runtime-guard.db'"
		echo "  sudo /usr/bin/runtime-guard event-summary --db '$state_dir/runtime-guard.db' --type file_write --limit 10"
	else
		echo "  rerun with --keep-installed or use a repo-built runtime-guard binary for CLI inspection"
	fi
	echo "Cleanup command after inspection:"
	echo "  sudo rm -rf -- '$state_dir'"
fi

exit "$validation_status"
