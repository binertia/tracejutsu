# Runtime Guard

Runtime Guard is a local-first runtime security analyst using eBPF event
compression and local LLM reasoning.

The current skeleton runs without root and exercises a fake-event pipeline:

```sh
go run ./cmd/runtime-guard demo
go test ./...
```

On Linux amd64, the live sensor streams normalized `execve`, IPv4 `connect`,
path-backed file write, and `chmod` attempt events as JSON. It uses raw
tracepoints and requires root or equivalent eBPF capabilities:

```sh
sudo go run ./cmd/runtime-guard run
sudo go test -tags=ebpf_smoke ./internal/ebpf -run 'Test(Execve|Connect|FileWrite|Chmod)CollectorSmoke'
```

The live collectors are assembled in Go, so they do not require `clang`. IPv6
collection is pending. File write and `chmod` events represent syscall-entry
attempts; successful completion tracking is a later hardening step.

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
The live collector also accepts `--db "$DB"` to persist normalized
events through a bounded async queue while streaming them. Supporting evidence
for an incident is upserted transactionally before links are created. A bounded in-memory
processor groups live process trees and flushes inactive candidates into
deterministic incidents. Tune its default 15-second inactivity threshold with
`--flush-after`. Active candidates retain at most 4096 recent events each and
65536 events in total. Compressed incident reports expose dropped older events.
Live collection prints ingestion, analysis, persistence, and kernel ring-buffer
drop counters every 10 seconds and at shutdown.

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
known limitations, validation commands, and recommended next task.
