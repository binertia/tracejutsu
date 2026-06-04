#!/usr/bin/env bash

runtime_guard_os_name() {
	if [[ -r /etc/os-release ]]; then
		(
			. /etc/os-release
			printf '%s' "${PRETTY_NAME:-unknown}"
		)
		return
	fi
	printf 'unknown'
}

runtime_guard_command_line() {
	local command_name=$1
	shift
	if ! command -v "$command_name" >/dev/null 2>&1; then
		printf 'unavailable'
		return
	fi
	"$command_name" "$@" 2>/dev/null | sed -n '1p'
}

runtime_guard_virtualization() {
	if ! command -v systemd-detect-virt >/dev/null 2>&1; then
		printf 'unknown'
		return
	fi
	local detected
	detected="$(systemd-detect-virt 2>/dev/null || true)"
	if [[ -z "$detected" ]]; then
		printf 'none'
		return
	fi
	printf '%s' "$detected"
}

runtime_guard_container() {
	if ! command -v systemd-detect-virt >/dev/null 2>&1; then
		printf 'unknown'
		return
	fi
	local detected
	detected="$(systemd-detect-virt --container 2>/dev/null || true)"
	if [[ -z "$detected" ]]; then
		printf 'none'
		return
	fi
	printf '%s' "$detected"
}

runtime_guard_cgroup_fs() {
	stat -fc '%T' /sys/fs/cgroup 2>/dev/null || printf 'unknown'
}

runtime_guard_print_host_fingerprint() {
	echo
	echo "===== host fingerprint ====="
	echo "hostname: $(hostname 2>/dev/null || printf 'unknown')"
	echo "os: $(runtime_guard_os_name)"
	echo "kernel: $(uname -srmo 2>/dev/null || printf 'unknown')"
	echo "arch: $(uname -m 2>/dev/null || printf 'unknown')"
	echo "systemd: $(runtime_guard_command_line systemctl --version)"
	echo "go: $(runtime_guard_command_line go version)"
	echo "cgroup_fs: $(runtime_guard_cgroup_fs)"
	echo "virtualization: $(runtime_guard_virtualization)"
	echo "container: $(runtime_guard_container)"
}

runtime_guard_require_sudo_access() {
	if sudo -n true 2>/dev/null; then
		return
	fi
	if [[ -t 0 ]]; then
		sudo -v
		return
	fi
	echo "sudo credentials are required before building temporary test artifacts" >&2
	echo "run this helper from an interactive terminal or configure non-interactive sudo" >&2
	exit 1
}

runtime_guard_print_validation_summary() {
	local run_status=$1
	local run_output=$2
	local journal_output=$3
	local final_stats
	final_stats="$(printf '%s\n' "$journal_output" | grep 'runtime stats:' | tail -n 1 || true)"

	echo
	echo "===== validation summary ====="
	echo "helper_exit: $run_status"
	printf '%s\n' "$run_output" |
		grep -E '^(Finished with result|Main processes terminated|Service runtime|CPU time consumed|Memory peak):' || true
	if [[ -n "$final_stats" ]]; then
		echo "final_runtime_stats: $final_stats"
		for counter in ring_dropped correlation_dropped persist_dropped incident_persist_dropped; do
			if [[ "$final_stats" == *"$counter=0"* ]]; then
				echo "$counter: ok"
			else
				echo "$counter: check"
			fi
		done
	else
		echo "final_runtime_stats: not found"
	fi
}
