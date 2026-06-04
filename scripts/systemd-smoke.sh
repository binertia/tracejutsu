#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: scripts/systemd-smoke.sh [--capabilities "CAP_BPF CAP_PERFMON ..."] [--yes]

Builds a temporary runtime-guard binary and runs it under a transient systemd
unit using the packaged service sandbox settings. This does not install,
replace, enable, or stop the real runtime-guard.service.

Options:
  --capabilities LIST  Space-separated CapabilityBoundingSet value to test.
                       Default keeps the packaged service capability set.
  --yes    Skip the interactive confirmation prompt.
  --help   Show this help.
EOF
}

capabilities="CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE"
assume_yes=0
while [[ $# -gt 0 ]]; do
	case "$1" in
	--capabilities)
		if [[ $# -lt 2 ]]; then
			echo "--capabilities requires a value" >&2
			exit 2
		fi
		capabilities="$2"
		shift 2
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

validate_capabilities() {
	if [[ -z "$1" ]]; then
		echo "--capabilities must not be empty" >&2
		exit 2
	fi
	local capability
	for capability in $1; do
		if [[ ! "$capability" =~ ^CAP_[A-Z0-9_]+$ ]]; then
			echo "invalid capability in --capabilities: $capability" >&2
			exit 2
		fi
	done
}

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

require_command go
require_command sudo
require_command install
require_command flock
require_command systemd-run
require_command systemctl
require_command journalctl
require_command mktemp
require_command tee
validate_capabilities "$capabilities"

lock_file=/tmp/runtime-guard-systemd-helper.lock
exec 9>"$lock_file"
if ! flock -n 9; then
	echo "another Runtime Guard systemd smoke/stress helper is already running" >&2
	echo "wait for it to finish before starting a new helper run" >&2
	exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
source "$repo_root/scripts/systemd-helper-lib.sh"

run_id="$(date +%Y%m%d%H%M%S)-$$"
unit="runtime-guard-smoke-$run_id"
service_unit="$unit.service"
state_name="$unit"
state_dir="/var/lib/$state_name"
repo_binary="$repo_root/bin/runtime-guard-smoke-$run_id"
repo_runner_script="$repo_root/bin/runtime-guard-smoke-runner-$run_id.sh"
state_binary="$state_dir/runtime-guard-smoke"
state_runner_script="$state_dir/runtime-guard-smoke-runner.sh"

cat <<EOF
Runtime Guard systemd smoke test

Will:
  - build: $repo_binary
  - build runner: $repo_runner_script
  - stage binary: $state_binary
  - stage runner: $state_runner_script
  - start transient unit: $service_unit
  - capabilities: $capabilities
  - write only inside service state: $state_dir
  - leave the real runtime-guard.service untouched

Will not:
  - install or replace packaging/systemd/runtime-guard.service
  - enable a boot service
  - write outside the repo build path and the dedicated service state directory
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

mkdir -p "$repo_root/bin"
GOCACHE="${GOCACHE:-/tmp/runtime-guard-gocache}" \
GOMODCACHE="${GOMODCACHE:-/tmp/runtime-guard-gomodcache}" \
	go build -trimpath -o "$repo_binary" ./cmd/runtime-guard

cat >"$repo_runner_script" <<'EOF'
#!/bin/sh
set -eu
guard_bin=$1
state_name=$2
state_dir="/var/lib/$state_name"
db="$state_dir/runtime-guard.db"

"$guard_bin" run --db "$db" --flush-after 2s --stats-interval 3s --event-buffer 16384 --persist-buffer 16384 --persist-batch-size 512 --ring-buffer-size 8388608 --quiet-events &
guard=$!

cleanup_guard() {
	if kill -0 "$guard" 2>/dev/null; then
		kill -TERM "$guard" 2>/dev/null || true
		wait "$guard" 2>/dev/null || true
	fi
}
trap cleanup_guard INT TERM EXIT

sleep 3
if ! kill -0 "$guard" 2>/dev/null; then
	wait "$guard"
	exit $?
fi

/bin/true || true
printf "runtime-guard smoke\n" > "$state_dir/smoke-file"
chmod +x "$state_dir/smoke-file"

if command -v bash >/dev/null 2>&1; then
	if command -v timeout >/dev/null 2>&1; then
		timeout 1s bash -c "</dev/tcp/127.0.0.1/1" 2>/dev/null || true
	else
		bash -c "</dev/tcp/127.0.0.1/1" 2>/dev/null || true
	fi
fi

sleep 5
if ! kill -0 "$guard" 2>/dev/null; then
	wait "$guard"
	exit $?
fi

kill -TERM "$guard"
wait "$guard" 2>/dev/null || true
trap - INT TERM EXIT
exit 0
EOF
chmod 0755 "$repo_runner_script"

sudo install -d -o root -g root -m 0700 "$state_dir"
sudo install -o root -g root -m 0755 "$repo_binary" "$state_binary"
sudo install -o root -g root -m 0755 "$repo_runner_script" "$state_runner_script"

systemd_args=(
	--unit="$unit"
	--wait
	-p Type=exec
	-p User=root
	-p Group=root
	-p UMask=0077
	-p StateDirectory="$state_name"
	-p StateDirectoryMode=0700
	-p ProtectSystem=strict
	-p ReadWritePaths="$state_dir"
	-p ProtectHome=read-only
	-p PrivateDevices=yes
	-p PrivateTmp=yes
	-p NoNewPrivileges=yes
	-p SystemCallArchitectures=native
	-p "CapabilityBoundingSet=$capabilities"
	-p LockPersonality=yes
	-p MemoryDenyWriteExecute=yes
	-p ProtectClock=yes
	-p ProtectControlGroups=yes
	-p ProtectHostname=yes
	-p ProtectKernelLogs=yes
	-p ProtectKernelModules=yes
	-p ProtectKernelTunables=yes
	-p RemoveIPC=yes
	-p RestrictNamespaces=yes
	-p RestrictRealtime=yes
	-p RestrictSUIDSGID=yes
	"$state_runner_script" "$state_binary" "$state_name"
)

run_output_file="$(mktemp -t runtime-guard-systemd-run.XXXXXX)"
set +e
sudo systemd-run "${systemd_args[@]}" 2>&1 | tee "$run_output_file"
run_status=${PIPESTATUS[0]}
set -e
run_output="$(cat "$run_output_file")"
rm -f "$run_output_file"

echo
echo "===== systemctl status $service_unit ====="
status_output="$(sudo systemctl status "$service_unit" --no-pager 2>&1)" || status_status=$?
if [[ "${status_status:-0}" -eq 0 ]]; then
	printf '%s\n' "$status_output"
elif [[ "$status_output" == *"could not be found"* ]]; then
	echo "transient unit already unloaded after systemd-run --wait; journal follows"
else
	printf '%s\n' "$status_output"
fi

echo
echo "===== journalctl -u $service_unit ====="
journal_output="$(sudo journalctl -u "$service_unit" -n 160 --no-pager 2>&1)" || journal_status=$?
printf '%s\n' "$journal_output"

runtime_guard_print_validation_summary "$run_status" "$run_output" "$journal_output"

echo
echo "State directory left for inspection: $state_dir"
echo "Cleanup command after inspection:"
echo "  sudo rm -rf -- '$state_dir'"
echo "  rm -f -- '$repo_binary'"
echo "  rm -f -- '$repo_runner_script'"

exit "$run_status"
