# Tracejutsu Install Guide

This guide installs the current MVP as a local Linux service. The service stores
all normalized events and incidents in a local SQLite database and does not call
any cloud service by default.

## Build

The module pins `toolchain go1.26.4` because `go1.26.3` has reachable standard
library vulnerability findings. Keep `GOTOOLCHAIN=auto` enabled or install Go
`1.26.4` or newer before building.

```sh
go test ./...
go build -trimpath -o ./bin/tracejutsu ./cmd/tracejutsu
```

For release artifacts, use the repository build script. It stamps
`tracejutsu version` metadata and writes SHA256 checksums:

```sh
scripts/build-release.sh --version v0.1.0
scripts/build-deb.sh --version v0.1.0 --maintainer "Your Name <you@example.com>"
```

When `rpmbuild` is available, an experimental RPM can also be built:

```sh
scripts/build-rpm.sh --version v0.1.0 --packager "Your Name <you@example.com>" --license "LicenseRef-Private"
```

On a fresh Fedora/RHEL-compatible validation host, test the RPM package
lifecycle before using the RPM on a personal machine or production host:

```sh
scripts/rpm-install-smoke.sh --rpm dist/tracejutsu-0.1.0-1.x86_64.rpm --duration 10m --yes
```

Set `SOURCE_DATE_EPOCH` to a Unix timestamp when repeatable release metadata
and archive/package timestamps are required.
Set `--maintainer` or `TRACEJUTSU_PACKAGE_MAINTAINER` before publishing a
Debian package for other users.
Set `--packager` or `TRACEJUTSU_PACKAGE_MAINTAINER` and a real `--license`
value before publishing an RPM package for other users.

Linux amd64 and native arm64 are supported for live eBPF collection. Build release
binaries natively on the target architecture when possible. Cross-building an
arm64 release binary from amd64 requires cgo and an aarch64 C compiler because
SQLite uses `github.com/mattn/go-sqlite3`. Native arm64 hardware validation is
tracked separately in [`ARM_TEST.md`](ARM_TEST.md):

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc \
  go build -trimpath -o ./bin/tracejutsu-linux-arm64 ./cmd/tracejutsu
```

## Install Binary

```sh
sudo install -o root -g root -m 0755 ./bin/tracejutsu /usr/local/bin/tracejutsu
```

Confirm the installed binary runs:

```sh
/usr/local/bin/tracejutsu --help
/usr/local/bin/tracejutsu version
```

If using the generated Debian package, install it with:

```sh
sudo apt install ./dist/tracejutsu_0.1.0_amd64.deb
```

The package installs `/usr/bin/tracejutsu` and
`/lib/systemd/system/tracejutsu.service`, but does not enable or start the
service automatically.

On a fresh Debian/Ubuntu validation host, test the full package lifecycle before
using the package on a personal machine or production host:

```sh
scripts/package-install-smoke.sh --deb dist/tracejutsu_0.1.0_amd64.deb --duration 2m --yes
```

The package smoke helper refuses existing Tracejutsu installs by default,
verifies the supplied package metadata and checksum when a sibling `.sha256`
file is present, verifies that the service was not auto-started or enabled,
starts the packaged service, validates final drop counters, stops the service,
removes the package, and leaves `/var/lib/tracejutsu` for inspection unless
`--purge-state` is supplied. Omit `--deb` only when you intentionally want the
helper to build and test a temporary package. Run it inside `tmux` or another
persistent session on SSH hosts so a client disconnect does not interrupt the
package cleanup path.
The RPM smoke helper follows the same safety model, using `--rpm` for release
artifacts and building a temporary RPM only when `--rpm` is omitted.

When you intentionally leave the package installed after validation, run the
operations helper to check the installed database, runtime stats, and online
backup path without stopping the service:

```sh
scripts/ops-validation.sh --yes
```

Before publishing artifacts, generate a single checksum manifest for the built
tarball, Debian package, and any RPM package. Add `--sign` to write and verify
an armored detached GPG signature:

```sh
scripts/release-manifest.sh --dir dist
scripts/release-manifest.sh --dir dist --sign
```

## Install Systemd Service

The included unit runs as root with `CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE`,
creates `/var/lib/tracejutsu` with `0700` permissions, and applies a systemd
sandbox that keeps writes limited to the state directory, hides host devices,
blocks namespace creation, restricts the service to the native syscall ABI, and
prevents writable-executable memory. It uses `--quiet-events` and
`--stats-interval 1m` so journald receives startup messages, incidents, and
periodic stats without every normalized event JSON line. It also raises burst
buffers with `--event-buffer 16384`, `--persist-buffer 16384`,
`--persist-batch-size 512`, and `--ring-buffer-size 8388608`. The private state
directory matches the SQLite path checks in the application: the database parent
directory must be owned by the service UID and must not permit group or other
writes.
The service enables all collectors by default. Add `--collectors` to the unit's
`ExecStart` only when you intentionally want a narrower deployment such as
`--collectors execve,connect`.
If file-write volume is too high on a host, test `--file-write-min-bytes`
before adding it to the service. A nonzero value filters smaller file writes in
the eBPF exit probe before they enter the ring buffer.
Tracejutsu excludes its own process PID from file-write capture so SQLite
persistence writes do not feed back into the collector.

```sh
sudo install -o root -g root -m 0644 \
  packaging/systemd/tracejutsu.service \
  /etc/systemd/system/tracejutsu.service

sudo systemctl daemon-reload
sudo systemctl enable --now tracejutsu.service
```

Check service health and logs:

```sh
sudo systemctl status tracejutsu.service
sudo journalctl -u tracejutsu.service -f
```

Inspect stored data:

```sh
sudo /usr/local/bin/tracejutsu events --db /var/lib/tracejutsu/tracejutsu.db
sudo /usr/local/bin/tracejutsu event-summary --db /var/lib/tracejutsu/tracejutsu.db --type file_write
sudo /usr/local/bin/tracejutsu db-stats --db /var/lib/tracejutsu/tracejutsu.db
sudo /usr/local/bin/tracejutsu incidents --db /var/lib/tracejutsu/tracejutsu.db
sudo /usr/local/bin/tracejutsu show --db /var/lib/tracejutsu/tracejutsu.db <incident_id>
```

See [`OPERATIONS.md`](OPERATIONS.md) for database growth, backup, compaction,
and journal retention guidance.

## Local LLM Analysis

LLM analysis is not part of the systemd service. Run it manually against a
stored incident after a local `llama-server` compatible endpoint is available:

```sh
llama-server --model /path/to/model.gguf --port 8080
sudo /usr/local/bin/tracejutsu llm --db /var/lib/tracejutsu/tracejutsu.db <incident_id>
sudo /usr/local/bin/tracejutsu show --db /var/lib/tracejutsu/tracejutsu.db <incident_id>
```

Remote LLM endpoints are rejected unless `--allow-remote-endpoint` is supplied.
Keep the default local-only behavior for normal operation.

## Capability Notes

The MVP service intentionally runs as root with a constrained systemd sandbox
and a narrow capability bounding set validated on the development Debian host.
That is the most predictable deployment mode for raw tracepoint eBPF collection.

A future least-privilege unit should be validated on the exact target kernel and
distribution. Depending on kernel version and procfs policy, it may need some
combination of:

- `CAP_BPF` and `CAP_PERFMON` for modern eBPF loading and tracing.
- `CAP_SYS_ADMIN` on older kernels or stricter distributions.
- `CAP_SYS_RESOURCE` if locked-memory limits are not automatically raised.
- `CAP_DAC_READ_SEARCH` or `CAP_SYS_PTRACE` for cross-process procfs metadata.

Do not assume a file-capability deployment is equivalent to the root service
until the root-only smoke tests and live enrichment have been revalidated.

To test a different capability set without changing the installed service, pass
`--capabilities` to the transient systemd helpers. The default matches the
packaged unit. Add back compatibility capabilities only if the default smoke
test fails:

```sh
scripts/systemd-smoke.sh

scripts/systemd-smoke.sh \
  --capabilities "CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE"

scripts/systemd-smoke.sh \
  --capabilities "CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_DAC_READ_SEARCH CAP_SYS_PTRACE"
```

After a passing fallback set is known, repeat the normal stress test with the
same `--capabilities` value. Only apply a wider service override after both
smoke and stress runs pass with zero drop counters:

```ini
[Service]
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE
```

## Root Smoke Test

Run the eBPF smoke tests before enabling the service on a new host:

```sh
sudo env \
  GOCACHE=/tmp/tracejutsu-gocache \
  GOMODCACHE="$(go env GOMODCACHE)" \
  "$(command -v go)" test -tags=ebpf_smoke ./internal/ebpf \
  -run 'Test(Execve|Connect|FileWrite|Chmod)CollectorSmoke' -v
```

On arm64 hosts, expect direct `chmod` user-space calls to appear as
`fchmodat`/`fchmodat2` events because arm64 does not expose the legacy direct
`chmod` syscall.
The arm64 collector targets native 64-bit processes; 32-bit compat syscall ABI
coverage has not been implemented. Use [`ARM_TEST.md`](ARM_TEST.md) for the
experimental arm64 VPS validation runbook.

## Systemd Sandbox Smoke Test

After the root eBPF smoke tests pass, run the packaged sandbox settings in a
transient unit before installing the service:

```sh
scripts/systemd-smoke.sh
```

The script builds a unique `bin/tracejutsu-smoke-*` binary and generated
runner, stages root-owned copies inside that unit's private
`/var/lib/tracejutsu-smoke-*` state directory, starts a unique
`tracejutsu-smoke-*` transient unit from the staged runner, prints the service
status or unload note plus journal, and leaves the real `tracejutsu.service`
untouched. Use `--capabilities` here to validate a different
`CapabilityBoundingSet` before creating a real service override.

## Systemd Stress Test

After the short smoke test passes, run a longer passive stress test under normal
host load:

```sh
scripts/systemd-stress.sh --duration 30m --stats-interval 1m
```

On Docker or Podman hosts, run `scripts/container-workload.sh` in a second
terminal while the stress helper is active to validate container metadata and
namespace behavior before claiming that host class as supported. See
[`STRESS_VALIDATION.md`](STRESS_VALIDATION.md) for the full container-host
workflow.

The stress helper uses the same sandbox and tuned buffer settings as the
packaged service unless `--capabilities` is supplied for least-privilege
validation. It does not install the service or generate artificial load.
The smoke and stress helpers use a shared local lock and refuse overlapping
helper runs; overlapping Tracejutsu runs can observe each other's SQLite WAL
writes and invalidate file-write drop results.
For repeatable multi-host validation, use the matrix in
[`STRESS_VALIDATION.md`](STRESS_VALIDATION.md).
Track the final `runtime stats` line, CPU time, memory peak, and whether
`ring_dropped`, `correlation_dropped`, `persist_dropped`, or
`incident_persist_dropped` remain zero. The smoke and stress helpers exit
nonzero if the transient unit fails, final runtime stats are missing, or any of
those required drop counters are nonzero. If ring drops are nonzero, also
capture `collector_ring_dropped` so the noisy collector can be tuned directly.
Record whether the host was plugged in or on battery and whether it was idle or
running other workload during the test.
If drops return, use `event-summary` against the stress database to inspect the
stored sample of high-volume processes and paths:

```sh
sudo ./bin/tracejutsu-stress-... event-summary --db /var/lib/tracejutsu-stress-.../tracejutsu.db --type file_write --limit 10
```

To isolate one collector after a nonzero drop breakdown, rerun with a narrower
collector set:

```sh
scripts/systemd-stress.sh --duration 10m --stats-interval 1m --collectors connect
scripts/systemd-stress.sh --duration 10m --stats-interval 1m --collectors file_write
```

If `file_write` is the noisy collector, test a kernel-side byte floor:

```sh
scripts/systemd-stress.sh --duration 10m --stats-interval 1m --collectors file_write --file-write-min-bytes 4096
```

This keeps only completed file writes whose return value is at least the
configured byte count. It reduces ordinary small writes but can miss small
sensitive-file edits, so treat it as a host-specific tuning decision. Runtime
Guard already excludes its own process PID from file-write capture, so test and
inspect `event-summary` before adding a byte floor to the installed service.

## Uninstall

If installed from the generated Debian package:

```sh
sudo systemctl disable --now tracejutsu.service
sudo dpkg -r tracejutsu
```

If installed manually:

```sh
sudo systemctl disable --now tracejutsu.service
sudo rm -f /etc/systemd/system/tracejutsu.service
sudo systemctl daemon-reload
```

The local database remains at `/var/lib/tracejutsu/tracejutsu.db` until it
is removed manually.
