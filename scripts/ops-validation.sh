#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: scripts/ops-validation.sh [--binary /usr/bin/tracejutsu] [--db /var/lib/tracejutsu/tracejutsu.db] [--backup-dir /var/backups/tracejutsu] [--skip-backup] [--allow-inactive] [--yes]

Validates basic operations behavior for an installed Tracejutsu service without
stopping the service or deleting data. The helper checks service state, database
privacy, db-stats output, WAL mode, event summaries, incident listing, recent
runtime stats from journald, and an optional SQLite online backup.

This helper is intended for hosts where Tracejutsu is already installed and the
state database is meant to remain for inspection.

Options:
  --binary PATH       Tracejutsu binary to use. Default: /usr/bin/tracejutsu.
  --db PATH           SQLite database path. Default:
                      /var/lib/tracejutsu/tracejutsu.db.
  --backup-dir DIR    Directory for the online backup. Default:
                      /var/backups/tracejutsu.
  --skip-backup       Do not create or integrity-check an online backup.
  --allow-inactive    Do not fail when tracejutsu.service is inactive.
  --yes               Skip the interactive confirmation prompt.
  --help              Show this help.
EOF
}

binary=/usr/bin/tracejutsu
db=/var/lib/tracejutsu/tracejutsu.db
backup_dir=/var/backups/tracejutsu
skip_backup=0
allow_inactive=0
assume_yes=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--binary)
		if [[ $# -lt 2 ]]; then
			echo "--binary requires a value" >&2
			exit 2
		fi
		binary=$2
		shift 2
		;;
	--db)
		if [[ $# -lt 2 ]]; then
			echo "--db requires a value" >&2
			exit 2
		fi
		db=$2
		shift 2
		;;
	--backup-dir)
		if [[ $# -lt 2 ]]; then
			echo "--backup-dir requires a value" >&2
			exit 2
		fi
		backup_dir=$2
		shift 2
		;;
	--skip-backup)
		skip_backup=1
		shift
		;;
	--allow-inactive)
		allow_inactive=1
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

validate_path() {
	local name=$1
	local value=$2
	if [[ "$value" != /* ]]; then
		echo "$name must be an absolute path: $value" >&2
		exit 2
	fi
	if [[ "$value" == *$'\n'* || "$value" == *$'\r'* || "$value" == *"'"* || "$value" =~ [[:cntrl:]] ]]; then
		echo "$name contains unsupported characters: $value" >&2
		exit 2
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

cleanup() {
	local status=$?
	trap - EXIT INT TERM HUP
	stop_sudo_keepalive
	exit "$status"
}

require_private_database_path() {
	if sudo test -L "$db"; then
		echo "database path is a symlink: $db" >&2
		exit 1
	fi
	if ! sudo test -f "$db"; then
		echo "database path is not a regular file: $db" >&2
		exit 1
	fi
	if ! sudo test -s "$db"; then
		echo "database path is empty: $db" >&2
		exit 1
	fi
}

run_tracejutsu() {
	sudo "$binary" "$@"
}

require_command bash
require_command date
require_command dirname
require_command grep
require_command journalctl
require_command sed
require_command sudo
require_command systemctl
if [[ "$skip_backup" -ne 1 ]]; then
	require_command install
	require_command sqlite3
fi

validate_path binary "$binary"
validate_path db "$db"
validate_path backup_dir "$backup_dir"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
source "$repo_root/scripts/systemd-helper-lib.sh"

if [[ "$assume_yes" -ne 1 ]]; then
	if [[ ! -t 0 ]]; then
		echo "refusing to run without --yes because stdin is not interactive" >&2
		exit 1
	fi
	cat <<EOF
Tracejutsu operations validation

Will:
  - inspect service state: tracejutsu.service
  - inspect binary: $binary
  - inspect database: $db
  - run db-stats, event-summary, and incidents
  - inspect recent journald runtime stats
  - create online backup: $([[ "$skip_backup" -eq 1 ]] && printf 'no' || printf 'yes')

Will not:
  - stop, start, enable, or disable tracejutsu.service
  - remove packages, logs, state, backups, or database rows
  - compact or vacuum the production database
EOF
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

tracejutsu_print_host_fingerprint

echo
echo "===== service state ====="
systemctl_status=0
sudo systemctl is-active --quiet tracejutsu.service || systemctl_status=$?
if [[ "$systemctl_status" -eq 0 ]]; then
	echo "tracejutsu.service: active"
elif [[ "$allow_inactive" -eq 1 ]]; then
	echo "tracejutsu.service: inactive (allowed)"
else
	echo "tracejutsu.service is not active" >&2
	exit 1
fi
sudo systemctl is-enabled --quiet tracejutsu.service && echo "tracejutsu.service: enabled" || echo "tracejutsu.service: not enabled"

echo
echo "===== binary version ====="
if ! sudo test -x "$binary"; then
	echo "binary is not executable: $binary" >&2
	exit 1
fi
run_tracejutsu version

echo
echo "===== database path ====="
require_private_database_path
sudo ls -ld "$(dirname "$db")"
sudo ls -l "$db"

echo
echo "===== db-stats ====="
db_stats="$(run_tracejutsu db-stats --db "$db")"
printf '%s\n' "$db_stats"
printf '%s\n' "$db_stats" | grep -F "journal_mode: wal" >/dev/null

echo
echo "===== event-summary file_write ====="
run_tracejutsu event-summary --db "$db" --type file_write --limit 10

echo
echo "===== incidents ====="
run_tracejutsu incidents --db "$db" --limit 10

echo
echo "===== recent runtime stats ====="
journal_output="$(sudo journalctl -u tracejutsu.service -n 120 --no-pager 2>&1)" || journal_status=$?
printf '%s\n' "$journal_output" | grep 'runtime stats:' | tail -n 5 || true
final_stats="$(tracejutsu_final_runtime_stats "$journal_output")"
if [[ -n "$final_stats" ]]; then
	echo "latest_runtime_stats: $final_stats"
else
	echo "latest_runtime_stats: not found"
fi

backup_path=""
if [[ "$skip_backup" -ne 1 ]]; then
	backup_path="$backup_dir/tracejutsu-$(date -u +%Y%m%dT%H%M%SZ).db"
	echo
	echo "===== online backup ====="
	sudo install -d -o root -g root -m 0700 "$backup_dir"
	sudo sqlite3 "$db" ".backup '$backup_path'"
	sudo chmod 0600 "$backup_path"
	sudo test -s "$backup_path"
	integrity="$(sudo sqlite3 "$backup_path" 'PRAGMA integrity_check;')"
	printf 'integrity_check: %s\n' "$integrity"
	if [[ "$integrity" != ok ]]; then
		echo "backup integrity check failed" >&2
		exit 1
	fi
	echo "backup_path: $backup_path"
fi

echo
echo "===== operations validation summary ====="
echo "service_active: $([[ "$systemctl_status" -eq 0 ]] && printf 'yes' || printf 'no')"
echo "journal_mode: wal"
if [[ -n "$final_stats" ]]; then
	echo "runtime_stats_seen: yes"
else
	echo "runtime_stats_seen: no"
fi
if [[ "$skip_backup" -eq 1 ]]; then
	echo "online_backup: skipped"
else
	echo "online_backup: pass"
	echo "backup_path: $backup_path"
fi
echo "validation_result: pass"
