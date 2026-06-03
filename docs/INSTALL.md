# Runtime Guard Install Guide

This guide installs the current MVP as a local Linux service. The service stores
all normalized events and incidents in a local SQLite database and does not call
any cloud service by default.

## Build

```sh
go test ./...
go build -trimpath -o ./bin/runtime-guard ./cmd/runtime-guard
```

## Install Binary

```sh
sudo install -o root -g root -m 0755 ./bin/runtime-guard /usr/local/bin/runtime-guard
```

Confirm the installed binary runs:

```sh
/usr/local/bin/runtime-guard --help
```

## Install Systemd Service

The included unit runs as root, creates `/var/lib/runtime-guard` with `0700`
permissions, and applies a systemd sandbox that keeps writes limited to the
state directory, hides host devices, blocks namespace creation, restricts the
service to the native syscall ABI, and prevents writable-executable memory. It
uses `--quiet-events` and `--stats-interval 1m` so journald receives startup
messages, incidents, and periodic stats without every normalized event JSON
line. It also raises burst buffers with `--event-buffer 16384`,
`--persist-buffer 16384`, `--persist-batch-size 512`, and
`--ring-buffer-size 8388608`. The private state directory matches the SQLite
path checks in the application: the database parent directory must be owned by
the service UID and must not permit group or other writes.
The service enables all collectors by default. Add `--collectors` to the unit's
`ExecStart` only when you intentionally want a narrower deployment such as
`--collectors execve,connect`.
If file-write volume is too high on a host, test `--file-write-min-bytes`
before adding it to the service. A nonzero value filters smaller file writes in
the eBPF exit probe before they enter the ring buffer.
Runtime Guard excludes its own process PID from file-write capture so SQLite
persistence writes do not feed back into the collector.

```sh
sudo install -o root -g root -m 0644 \
  packaging/systemd/runtime-guard.service \
  /etc/systemd/system/runtime-guard.service

sudo systemctl daemon-reload
sudo systemctl enable --now runtime-guard.service
```

Check service health and logs:

```sh
sudo systemctl status runtime-guard.service
sudo journalctl -u runtime-guard.service -f
```

Inspect stored data:

```sh
sudo /usr/local/bin/runtime-guard events --db /var/lib/runtime-guard/runtime-guard.db
sudo /usr/local/bin/runtime-guard event-summary --db /var/lib/runtime-guard/runtime-guard.db --type file_write
sudo /usr/local/bin/runtime-guard incidents --db /var/lib/runtime-guard/runtime-guard.db
sudo /usr/local/bin/runtime-guard show --db /var/lib/runtime-guard/runtime-guard.db <incident_id>
```

## Local LLM Analysis

LLM analysis is not part of the systemd service. Run it manually against a
stored incident after a local `llama-server` compatible endpoint is available:

```sh
llama-server --model /path/to/model.gguf --port 8080
sudo /usr/local/bin/runtime-guard llm --db /var/lib/runtime-guard/runtime-guard.db <incident_id>
sudo /usr/local/bin/runtime-guard show --db /var/lib/runtime-guard/runtime-guard.db <incident_id>
```

Remote LLM endpoints are rejected unless `--allow-remote-endpoint` is supplied.
Keep the default local-only behavior for normal operation.

## Capability Notes

The MVP service intentionally runs as root with a constrained systemd sandbox.
That is the most predictable deployment mode for raw tracepoint eBPF collection
and procfs enrichment.

A future least-privilege unit should be validated on the exact target kernel and
distribution. Depending on kernel version and procfs policy, it may need some
combination of:

- `CAP_BPF` and `CAP_PERFMON` for modern eBPF loading and tracing.
- `CAP_SYS_ADMIN` on older kernels or stricter distributions.
- `CAP_SYS_RESOURCE` if locked-memory limits are not automatically raised.
- `CAP_DAC_READ_SEARCH` or `CAP_SYS_PTRACE` for cross-process procfs metadata.

Do not assume a file-capability deployment is equivalent to the root service
until the root-only smoke tests and live enrichment have been revalidated.

## Root Smoke Test

Run the eBPF smoke tests before enabling the service on a new host:

```sh
sudo env \
  GOCACHE=/tmp/runtime-guard-gocache \
  GOMODCACHE="$(go env GOMODCACHE)" \
  "$(command -v go)" test -tags=ebpf_smoke ./internal/ebpf \
  -run 'Test(Execve|Connect|FileWrite|Chmod)CollectorSmoke' -v
```

## Systemd Sandbox Smoke Test

After the root eBPF smoke tests pass, run the packaged sandbox settings in a
transient unit before installing the service:

```sh
scripts/systemd-smoke.sh
```

The script builds a unique `bin/runtime-guard-smoke-*` binary and generated
runner, starts a unique `runtime-guard-smoke-*` transient unit, writes only to
that unit's private `/var/lib/runtime-guard-smoke-*` state directory, prints the
service status or unload note plus journal, and leaves the real
`runtime-guard.service` untouched.

## Systemd Stress Test

After the short smoke test passes, run a longer passive stress test under normal
host load:

```sh
scripts/systemd-stress.sh --duration 30m --stats-interval 1m
```

The stress helper uses the same sandbox and tuned buffer settings as the
packaged service. It does not install the service or generate artificial load.
Track the final `runtime stats` line, CPU time, memory peak, and whether
`ring_dropped`, `correlation_dropped`, or `persist_dropped` remain zero. If
ring drops are nonzero, also capture `collector_ring_dropped` so the noisy
collector can be tuned directly.
Use `event-summary` against the stress database to inspect the stored sample of
high-volume processes and paths:

```sh
sudo ./bin/runtime-guard-stress-... event-summary --db /var/lib/runtime-guard-stress-.../runtime-guard.db --type file_write --limit 10
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
sensitive-file edits, so treat it as a host-specific tuning decision.

## Uninstall

```sh
sudo systemctl disable --now runtime-guard.service
sudo rm -f /etc/systemd/system/runtime-guard.service
sudo systemctl daemon-reload
```

The local database remains at `/var/lib/runtime-guard/runtime-guard.db` until it
is removed manually.
