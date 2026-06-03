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
permissions. It uses `--quiet-events` and `--stats-interval 1m` so journald
receives startup messages, incidents, and periodic stats without every
normalized event JSON line. The private state directory matches the SQLite path
checks in the application: the database parent directory must be owned by the
service UID and must not permit group or other writes.

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

## Uninstall

```sh
sudo systemctl disable --now runtime-guard.service
sudo rm -f /etc/systemd/system/runtime-guard.service
sudo systemctl daemon-reload
```

The local database remains at `/var/lib/runtime-guard/runtime-guard.db` until it
is removed manually.
