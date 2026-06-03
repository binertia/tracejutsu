#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: scripts/systemd-stress.sh [--duration 30m] [--stats-interval 1m] [--yes]

Builds a temporary runtime-guard binary and runs it under a transient systemd
unit using the packaged service sandbox and tuned buffer settings. This is a
longer passive stress run: it observes normal host activity and does not install,
replace, enable, or stop the real runtime-guard.service.

Options:
  --duration DURATION        How long to run the transient service. Default: 30m.
  --stats-interval DURATION  Runtime stats print interval. Default: 1m.
  --yes                      Skip the interactive confirmation prompt.
  --help                     Show this help.
EOF
}

duration=30m
stats_interval=1m
assume_yes=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--duration)
		if [[ $# -lt 2 ]]; then
			echo "--duration requires a value" >&2
			exit 2
		fi
		duration="$2"
		shift 2
		;;
	--stats-interval)
		if [[ $# -lt 2 ]]; then
			echo "--stats-interval requires a value" >&2
			exit 2
		fi
		stats_interval="$2"
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

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

require_command go
require_command sudo
require_command systemd-run
require_command systemctl
require_command journalctl
require_command timeout

if ! timeout "$duration" true >/dev/null 2>&1; then
	echo "invalid --duration for timeout/sleep: $duration" >&2
	exit 2
fi
if ! timeout "$stats_interval" true >/dev/null 2>&1; then
	echo "invalid --stats-interval for timeout/sleep: $stats_interval" >&2
	exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case "$repo_root" in
/tmp/*|/var/tmp/*)
	echo "refusing to run from $repo_root because PrivateTmp may hide the binary from the transient service" >&2
	exit 1
	;;
esac
cd "$repo_root"

run_id="$(date +%Y%m%d%H%M%S)-$$"
unit="runtime-guard-stress-$run_id"
service_unit="$unit.service"
state_name="$unit"
state_dir="/var/lib/$state_name"
binary="$repo_root/bin/runtime-guard-stress-$run_id"
runner_script="$repo_root/bin/runtime-guard-stress-runner-$run_id.sh"

cat <<EOF
Runtime Guard systemd stress test

Will:
  - build: $binary
  - build runner: $runner_script
  - start transient unit: $service_unit
  - run duration: $duration
  - stats interval: $stats_interval
  - write only inside service state: $state_dir
  - leave the real runtime-guard.service untouched

Tuned runtime settings:
  - event_buffer=16384
  - persist_buffer=16384
  - persist_batch_size=512
  - ring_buffer_size=8388608

Will not:
  - install or replace packaging/systemd/runtime-guard.service
  - enable a boot service
  - generate artificial load
  - write outside the repo build path and the dedicated service state directory
EOF

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

mkdir -p "$repo_root/bin"
GOCACHE="${GOCACHE:-/tmp/runtime-guard-gocache}" \
GOMODCACHE="${GOMODCACHE:-/tmp/runtime-guard-gomodcache}" \
	go build -trimpath -o "$binary" ./cmd/runtime-guard

cat >"$runner_script" <<'EOF'
#!/bin/sh
set -eu
guard_bin=$1
state_name=$2
duration=$3
stats_interval=$4
state_dir="/var/lib/$state_name"
db="$state_dir/runtime-guard.db"

"$guard_bin" run \
	--db "$db" \
	--flush-after 15s \
	--stats-interval "$stats_interval" \
	--event-buffer 16384 \
	--persist-buffer 16384 \
	--persist-batch-size 512 \
	--ring-buffer-size 8388608 \
	--quiet-events &
guard=$!

cleanup_guard() {
	if kill -0 "$guard" 2>/dev/null; then
		kill -TERM "$guard" 2>/dev/null || true
		wait "$guard" 2>/dev/null || true
	fi
}
trap cleanup_guard INT TERM EXIT

sleep 5
if ! kill -0 "$guard" 2>/dev/null; then
	wait "$guard"
	exit $?
fi

sleep "$duration"
if ! kill -0 "$guard" 2>/dev/null; then
	wait "$guard"
	exit $?
fi

kill -TERM "$guard"
wait "$guard" 2>/dev/null || true
trap - INT TERM EXIT
exit 0
EOF
chmod 0755 "$runner_script"

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
	-p 'CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH CAP_SYS_PTRACE'
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
	"$runner_script" "$binary" "$state_name" "$duration" "$stats_interval"
)

set +e
sudo systemd-run "${systemd_args[@]}"
run_status=$?
set -e

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
sudo journalctl -u "$service_unit" -n 240 --no-pager || true

echo
echo "State directory left for inspection: $state_dir"
echo "Useful inspection commands:"
echo "  sudo du -h '$state_dir'"
echo "  sudo '$binary' incidents --db '$state_dir/runtime-guard.db'"
echo "  sudo '$binary' events --db '$state_dir/runtime-guard.db' --limit 5"
echo "Cleanup command after inspection:"
echo "  sudo rm -rf -- '$state_dir'"
echo "  rm -f -- '$binary'"
echo "  rm -f -- '$runner_script'"

exit "$run_status"
