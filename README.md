# Runtime Guard

Runtime Guard is a local-first runtime security analyst using eBPF event
compression and local LLM reasoning.

The current skeleton runs without root and exercises a fake-event pipeline:

```sh
go run ./cmd/runtime-guard demo
go test ./...
```

On Linux amd64 and native arm64, the live sensor streams normalized `execve`,
IPv4/IPv6 `connect`, path-backed file write, and `chmod` events as JSON. It uses raw
tracepoints and requires root or equivalent eBPF capabilities:

```sh
sudo go run ./cmd/runtime-guard run
sudo go test -tags=ebpf_smoke ./internal/ebpf -run 'Test(Execve|Connect|FileWrite|Chmod)CollectorSmoke'
```

The live collectors are assembled in Go, so they do not require `clang`.
`connect`, file write, and `chmod` probes correlate syscall entry and exit with
bounded in-kernel maps. File write and chmod report `success` or `failed`.
Connect reports `success`, `in_progress`, or `failed` because non-blocking
clients often return `EINPROGRESS`. A requested chmod execute bit does not
prove that the bit was newly added.
On arm64, direct `chmod` libc calls are captured through the `fchmodat` family
provided by the arm64 syscall ABI. Arm64 live hardware validation is tracked as
an experiment in [`docs/ARM_TEST.md`](docs/ARM_TEST.md).

Persist the fake pipeline to a local SQLite database and inspect the result:

```sh
mkdir -p "$HOME/.local/state/runtime-guard"
chmod 700 "$HOME/.local/state/runtime-guard"
DB="$HOME/.local/state/runtime-guard/runtime-guard.db"
go run ./cmd/runtime-guard demo --db "$DB"
go run ./cmd/runtime-guard events --db "$DB"
go run ./cmd/runtime-guard incidents --db "$DB"
go run ./cmd/runtime-guard show --db "$DB" inc-evt-001
```

SQLite uses WAL mode. New database files are created with `0600` permissions;
existing database paths must be private regular files rather than symlinks.
The database parent directory must be owned by the running user and must not
permit group or other writes.
The live collector also accepts `--db "$DB"` to persist normalized events and
incidents through bounded async queues while streaming them. Supporting evidence
for an incident is upserted transactionally before links are created. A bounded
in-memory processor groups live process trees and flushes inactive candidates
into deterministic incidents. Tune its default 15-second inactivity threshold
with `--flush-after`. Use `--quiet-events` for service-style runs that should
print incidents and stats without per-event JSON. Tune periodic stats with
`--stats-interval`; `0` disables periodic stats but still prints final shutdown
stats. Burst buffers can be tuned with `--event-buffer`, `--persist-buffer`,
`--persist-batch-size`, and `--ring-buffer-size`. Active candidates retain at
most 4096 recent events each and 65536 events in total. Compressed incident
reports expose dropped older events. Live collection prints ingestion,
analysis, event and incident persistence, kernel ring-buffer drop, and
syscall-correlation-drop counters every 10 seconds by default and at shutdown.

Analyze a stored incident with a local `llama-server`-compatible HTTP endpoint:

```sh
llama-server --model /path/to/model.gguf --port 8080
go run ./cmd/runtime-guard llm --db "$DB" inc-evt-001
```

The LLM receives compressed incident JSON only. The client accepts loopback
endpoints by default, constrains llama-server output with a JSON Schema,
enforces a default 5-minute timeout, and stores validated JSON reports
separately from deterministic incident scores. Override the timeout with
`--timeout`. Use `--allow-remote-endpoint` only for an explicitly configured
remote service. Raw LLM output is discarded unless `--preserve-raw-response`
is set. If the local server requires an API key, set
`RUNTIME_GUARD_LLM_API_KEY`.

See [`docs/RUNTIME_AI_GUARD_PLAN.md`](docs/RUNTIME_AI_GUARD_PLAN.md) for the
architecture and phased implementation plan. See
[`docs/HANDOFF.md`](docs/HANDOFF.md) for the current implementation status,
known limitations, validation commands, and recommended next task. See
[`docs/INSTALL.md`](docs/INSTALL.md) for local service installation and
systemd deployment notes, including transient capability validation before
installing a narrower service override. See [`docs/ARM_TEST.md`](docs/ARM_TEST.md)
for the separate native arm64 VPS experiment and
[`docs/STRESS_VALIDATION.md`](docs/STRESS_VALIDATION.md) for the active
multi-host validation track.
