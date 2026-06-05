#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
source "$repo_root/scripts/systemd-helper-lib.sh"

usage() {
	cat <<'EOF'
Usage: scripts/container-workload.sh [--runtime auto|docker|podman] [--image IMAGE] [--duration 5m] [--interval 2s] [--pull never|missing|always] [--yes]

Runs a small unprivileged container workload while Runtime Guard is already
running on the host. The workload produces exec, file write, chmod, and local
loopback connect attempts from inside a container so a concurrent stress run can
validate container metadata and namespace behavior.

Options:
  --runtime NAME       Container runtime: auto, docker, or podman. Default: auto.
  --image IMAGE        Container image to run. Default: alpine:3.20.
  --duration DURATION  How long to run. Default: 5m.
  --interval DURATION  Sleep between workload loops inside the container. Default: 2s.
  --pull POLICY        Container pull policy. Default: never.
                       Use "missing" only when network image pulls are acceptable.
  --yes                Skip the interactive confirmation prompt.
  --help               Show this help.
EOF
}

runtime=auto
image=alpine:3.20
duration=5m
interval=2s
pull_policy=never
assume_yes=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--runtime)
		if [[ $# -lt 2 ]]; then
			echo "--runtime requires a value" >&2
			exit 2
		fi
		runtime=$2
		shift 2
		;;
	--image)
		if [[ $# -lt 2 ]]; then
			echo "--image requires a value" >&2
			exit 2
		fi
		image=$2
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
	--interval)
		if [[ $# -lt 2 ]]; then
			echo "--interval requires a value" >&2
			exit 2
		fi
		interval=$2
		shift 2
		;;
	--pull)
		if [[ $# -lt 2 ]]; then
			echo "--pull requires a value" >&2
			exit 2
		fi
		pull_policy=$2
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

resolve_runtime() {
	case "$runtime" in
	auto)
		if command -v docker >/dev/null 2>&1; then
			printf 'docker'
			return
		fi
		if command -v podman >/dev/null 2>&1; then
			printf 'podman'
			return
		fi
		echo "missing container runtime: install docker or podman, or pass --runtime" >&2
		exit 1
		;;
	docker|podman)
		if ! command -v "$runtime" >/dev/null 2>&1; then
			echo "missing container runtime: $runtime" >&2
			exit 1
		fi
		printf '%s' "$runtime"
		;;
	*)
		echo "invalid --runtime: $runtime" >&2
		exit 2
		;;
	esac
}

case "$pull_policy" in
never|missing|always)
	;;
*)
	echo "invalid --pull policy: $pull_policy" >&2
	exit 2
	;;
esac

require_command date
require_command hostname
require_command tail
require_command timeout

if ! timeout "$duration" true >/dev/null 2>&1; then
	echo "invalid --duration for timeout: $duration" >&2
	exit 2
fi
if ! timeout "$interval" true >/dev/null 2>&1; then
	echo "invalid --interval for timeout/sleep: $interval" >&2
	exit 2
fi

container_runtime="$(resolve_runtime)"
container_name="runtime-guard-container-workload-$(date +%Y%m%d%H%M%S)-$$"

if [[ "$pull_policy" == "never" ]]; then
	if ! "$container_runtime" image inspect "$image" >/dev/null 2>&1; then
		echo "container image is not present locally: $image" >&2
		echo "pull it explicitly first, or rerun with --pull missing if network pulls are acceptable" >&2
		exit 1
	fi
fi

cat <<EOF
Runtime Guard container workload

Will:
  - runtime: $container_runtime
  - image: $image
  - container name: $container_name
  - duration: $duration
  - interval: $interval
  - pull policy: $pull_policy
  - run without host mounts
  - run without host network access
  - drop all container capabilities

Will not:
  - install or replace Runtime Guard
  - start or stop runtime-guard.service
  - mount host directories into the container
  - intentionally connect to external networks
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

cleanup() {
	"$container_runtime" rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup INT TERM EXIT

workload='
set -eu
interval=$1
workdir=/tmp/runtime-guard-container-workload
mkdir -p "$workdir"
i=0
echo "runtime-guard container workload started"
while :; do
	i=$((i + 1))
	/bin/true || true
	probe="$workdir/probe-$i.sh"
	printf "%s\n%s\n" "#!/bin/sh" "exit 0" >"$probe"
	chmod +x "$probe"
	"$probe" >/dev/null 2>&1 || true
	printf "runtime-guard container workload %s\n" "$i" >>"$workdir/events.log"
	chmod 600 "$workdir/events.log"
	if command -v nc >/dev/null 2>&1; then
		nc -z -w 1 127.0.0.1 1 >/dev/null 2>&1 || true
	elif command -v wget >/dev/null 2>&1; then
		wget -q -T 1 -O /dev/null http://127.0.0.1:1/ >/dev/null 2>&1 || true
	fi
	rm -f "$probe"
	sleep "$interval"
done
'

run_args=(
	run
	--rm
	--name "$container_name"
	--pull "$pull_policy"
	--network none
	--cap-drop ALL
	--security-opt no-new-privileges
	--tmpfs /tmp:rw,nosuid,nodev,size=16m
	"$image"
	sh -eu -c "$workload" sh "$interval"
)

set +e
"$container_runtime" "${run_args[@]}" &
container_client=$!
timeout "$duration" tail --pid="$container_client" -f /dev/null >/dev/null 2>&1
timeout_status=$?
if [[ "$timeout_status" -eq 124 ]]; then
	"$container_runtime" rm -f "$container_name" >/dev/null 2>&1 || true
fi
wait "$container_client"
run_status=$?
set -e

trap - INT TERM EXIT
cleanup

if [[ "$timeout_status" -eq 124 ]]; then
	echo "container workload completed requested duration: $duration"
	exit 0
fi

if [[ "$run_status" -eq 0 ]]; then
	echo "container workload exited before requested duration"
	exit 0
fi

echo "container workload failed with status: $run_status" >&2
exit "$run_status"
