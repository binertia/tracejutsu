# Tracejutsu

Tracejutsu is a local Linux security tool. It watches runtime activity with
eBPF, groups related events into incidents, stores them in SQLite, and can ask a
local LLM to explain an incident.

It is local-first: events stay on the machine unless you explicitly configure a
remote LLM endpoint.

## What It Captures

By default, live mode watches:

- process starts (`execve`)
- outbound network connections
- file writes
- permission changes (`chmod`)

For lab investigations, `--collectors behavior_core` adds broader behavior
signals such as sensitive file reads, namespace changes, process access, and
network server activity.

## Current Release Scope

`v0.1.0` is validated for **Debian 13 (trixie) amd64**.

The live collector can also run on Linux amd64 and native arm64, but other
systems are not part of the validated release target yet.

## Quick Start

Run the demo first. It does not need root and does not use eBPF:

```sh
go run ./cmd/tracejutsu demo
```

Run the tests:

```sh
go test ./...
```

The module uses Go toolchain `go1.26.4`. Keep `GOTOOLCHAIN=auto` enabled or
install Go `1.26.4` or newer.

## Save Demo Results

Initialize a private SQLite database path, then reuse it through
`TRACEJUTSU_DB`:

```sh
export TRACEJUTSU_DB="$HOME/.local/state/tracejutsu/tracejutsu.db"

go run ./cmd/tracejutsu init
go run ./cmd/tracejutsu doctor
go run ./cmd/tracejutsu demo --db "$TRACEJUTSU_DB"
go run ./cmd/tracejutsu triage
go run ./cmd/tracejutsu show inc-evt-001
```

Useful database commands:

```sh
go run ./cmd/tracejutsu events --type execve --process payload
go run ./cmd/tracejutsu incidents --llm-status pending
go run ./cmd/tracejutsu event-summary --type file_write
go run ./cmd/tracejutsu db-stats --format json
```

## Live Capture

Live capture needs Linux and root, or equivalent eBPF capabilities:

```sh
sudo go run ./cmd/tracejutsu run
```

Save live events and incidents:

```sh
sudo install -d -o root -g root -m 0700 /var/lib/tracejutsu
sudo go run ./cmd/tracejutsu run --db /var/lib/tracejutsu/tracejutsu.db
```

For service-style output, hide per-event JSON and print incidents plus runtime
stats:

```sh
sudo go run ./cmd/tracejutsu run --db /var/lib/tracejutsu/tracejutsu.db --quiet-events
```

Enable the broader lab collector set:

```sh
sudo go run ./cmd/tracejutsu run --collectors behavior_core
```

Press `Ctrl-C` to stop. Tracejutsu prints final runtime stats at shutdown.

## Local LLM Analysis

LLM analysis is optional. Start a local `llama-server` compatible endpoint, then
analyze a stored incident:

```sh
llama-server --model /path/to/model.gguf --port 8080
go run ./cmd/tracejutsu llm inc-evt-001
go run ./cmd/tracejutsu show inc-evt-001
```

Analyze pending incidents in priority order:

```sh
go run ./cmd/tracejutsu llm --all-pending --min-score 60 --limit 10
```

Remote LLM endpoints are blocked unless you pass `--allow-remote-endpoint`.
If your local server requires an API key, set `TRACEJUTSU_LLM_API_KEY`.

## Install As A Service

Build a binary:

```sh
go build -trimpath -o ./bin/tracejutsu ./cmd/tracejutsu
```

Install guide:

- [docs/INSTALL.md](docs/INSTALL.md) - binary, Debian package, systemd service,
  release builds, and validation
- [docs/OPERATIONS.md](docs/OPERATIONS.md) - database size, backups,
  compaction, and logs

## Validation

Fast local release check:

```sh
scripts/release-check.sh
```

Fresh disposable Debian/Ubuntu host validation:

```sh
./test.sh --quick --yes
```

Full validation:

```sh
./test.sh --yes
```

## Command Summary

```text
tracejutsu init [--db path]
tracejutsu doctor [--db path] [--service]
tracejutsu demo [--db path] [fixture.json]
tracejutsu run [--db path] [--collectors list] [--quiet-events]
tracejutsu events [--db path] [--limit count] [--type event_type] [--process name] [--pid pid] [--container-id id] [--since time] [--until time]
tracejutsu event-summary [--db path] [--type event_type] [--format text|json]
tracejutsu db-stats [--db path] [--format text|json]
tracejutsu incidents [--db path] [--limit count] [--llm-status status] [--since time] [--until time] [--format text|json]
tracejutsu triage [--db path] [--limit count] [--min-score score] [--evidence-limit count] [--llm-status status] [--since time] [--until time] [--format text|json]
tracejutsu show [--db path] [--evidence-limit count] [--format text|json] <incident_id>
tracejutsu llm [--db path] <incident_id>
tracejutsu llm [--db path] --all-pending [--min-score score] [--limit count]
tracejutsu rules [--format text|json]
tracejutsu config
tracejutsu version
```

## More Docs

- [examples/README.md](examples/README.md) - demo fixture notes
- [docs/TRACEJUTSU_PLAN.md](docs/TRACEJUTSU_PLAN.md) - architecture and roadmap
- [docs/HANDOFF.md](docs/HANDOFF.md) - current status and known limitations
- [docs/ARM_TEST.md](docs/ARM_TEST.md) - arm64 validation notes
- [docs/STRESS_VALIDATION.md](docs/STRESS_VALIDATION.md) - stress validation
