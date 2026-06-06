# Tracejutsu

Tracejutsu is a local-first runtime security analyst using eBPF event
compression and local LLM reasoning.

The current skeleton runs without root and exercises a fake-event pipeline:

```sh
go run ./cmd/tracejutsu demo
go test ./...
```

On Linux amd64 and native arm64, the default live sensor streams normalized
`execve`, IPv4/IPv6 `connect`, path-backed file write, and `chmod` events as
JSON. It uses raw tracepoints and requires root or equivalent eBPF
capabilities:

```sh
sudo go run ./cmd/tracejutsu run
sudo go test -tags=ebpf_smoke ./internal/ebpf \
  -run 'Test(Execve|Connect|FileWrite|Chmod|SensitiveRead|FileLifecycle|PrivilegeChange|NamespaceChange|ProcessAccess|NetworkServer|KernelTamper)CollectorSmoke'
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

For security-lab and behavior-chain investigation, opt in to the broader
behavior-core collector set:

```sh
sudo go run ./cmd/tracejutsu run --collectors behavior_core
```

`behavior_core` adds `sensitive_read`, `file_lifecycle`, `privilege_change`,
`namespace_change`, `process_access`, `network_server`, and `kernel_tamper`
events while preserving the default four collectors. These categories are not
enabled by `all` until separate stress validation proves their production noise
and drop behavior.

Persist the fake pipeline to a local SQLite database and inspect the result:

```sh
mkdir -p "$HOME/.local/state/tracejutsu"
chmod 700 "$HOME/.local/state/tracejutsu"
DB="$HOME/.local/state/tracejutsu/tracejutsu.db"
go run ./cmd/tracejutsu demo --db "$DB"
go run ./cmd/tracejutsu events --db "$DB"
go run ./cmd/tracejutsu incidents --db "$DB"
go run ./cmd/tracejutsu show --db "$DB" inc-evt-001
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
`--persist-batch-size`, and `--ring-buffer-size`. Use `--collectors` to select
`all`, `behavior_core`, or an explicit comma-separated collector subset. Active
candidates retain at most 4096 recent events each and 65536 events in total.
Compressed incident reports expose dropped older events. Live collection prints
ingestion, analysis, event and incident persistence, kernel ring-buffer drop,
and syscall-correlation-drop counters every 10 seconds by default and at
shutdown.

Analyze a stored incident with a local `llama-server`-compatible HTTP endpoint:

```sh
llama-server --model /path/to/model.gguf --port 8080
go run ./cmd/tracejutsu llm --db "$DB" inc-evt-001
```

The LLM receives compressed incident JSON only. The client accepts loopback
endpoints by default, constrains llama-server output with a JSON Schema,
enforces a default 5-minute timeout, and stores validated JSON reports
separately from deterministic incident scores. Override the timeout with
`--timeout`. Use `--allow-remote-endpoint` only for an explicitly configured
remote service. Raw LLM output is discarded unless `--preserve-raw-response`
is set. If the local server requires an API key, set
`TRACEJUTSU_LLM_API_KEY`.

See [`docs/TRACEJUTSU_PLAN.md`](docs/TRACEJUTSU_PLAN.md) for the
architecture and phased implementation plan. See
[`docs/HANDOFF.md`](docs/HANDOFF.md) for the current implementation status,
known limitations, validation commands, and recommended next task. See
[`docs/INSTALL.md`](docs/INSTALL.md) for local service installation and
systemd deployment notes, including transient capability validation before
installing a narrower service override. See [`docs/ARM_TEST.md`](docs/ARM_TEST.md)
for the separate native arm64 VPS experiment and
[`docs/STRESS_VALIDATION.md`](docs/STRESS_VALIDATION.md) for the active
multi-host validation track. See [`docs/OPERATIONS.md`](docs/OPERATIONS.md)
for database growth, backup, compaction, and journal retention guidance.

For the non-root local release gate used before publishing or packaging, run:

```sh
scripts/release-check.sh
```

On a fresh disposable Debian/Ubuntu validation host, bootstrap dependencies and
run the full validation path with:

```sh
./test.sh --yes
```

Use `./test.sh --quick --yes` for a shorter first pass.

If the VPS validation user should not run the whole script through `sudo`, use
the split phases with one shared logs directory:

```sh
logs=validation-artifacts/fresh-host-vps
sudo ./test.sh --phase setup --logs-dir "$logs" --yes
./test.sh --phase user --logs-dir "$logs" --yes
sudo ./test.sh --phase root --logs-dir "$logs" --yes
```

The `sudo` form auto-detects the Go toolchain installed by the user phase. From
a direct root shell, pass
`--go-bin /home/USER/.local/share/tracejutsu-go/goVERSION/bin/go` if Go is not
already in root's `PATH`.

To build a version-stamped release tarball for the current Linux architecture:

```sh
scripts/build-release.sh --version v0.1.0
```

To build a Debian package for the current Linux architecture:

```sh
scripts/build-deb.sh --version v0.1.0 --maintainer "Your Name <you@example.com>"
```

To build a complete release directory with tarball, Debian package, dependency
review, checksum manifest, and optional signature:

```sh
scripts/release-bundle.sh --version v0.1.0 --maintainer "Your Name <you@example.com>"
scripts/release-bundle.sh --version v0.1.0 --maintainer "Your Name <you@example.com>" --sign
```

To build an experimental RPM package when `rpmbuild` is available:

```sh
scripts/build-rpm.sh --version v0.1.0 --packager "Your Name <you@example.com>" --license "LicenseRef-Private"
```

On a fresh Fedora/RHEL-compatible validation host, smoke test the RPM lifecycle:

```sh
scripts/rpm-install-smoke.sh --rpm dist/tracejutsu-0.1.0-1.x86_64.rpm --duration 10m --yes
```

Set `SOURCE_DATE_EPOCH` to a Unix timestamp when repeatable release metadata
and archive/package timestamps are required.

On a fresh Debian/Ubuntu validation host, run the installed package smoke test
against the release `.deb`:

```sh
scripts/package-install-smoke.sh --deb dist/tracejutsu_0.1.0_amd64.deb --duration 2m --yes
```

To generate an experimental static APT repository from release `.deb` files:

```sh
scripts/build-apt-repo.sh --deb dist/tracejutsu_0.1.0_amd64.deb --out dist/apt-repo --sign
```

On a fresh Debian/Ubuntu validation host, test installation through that APT
source. Use `--apt-trusted` only for local unsigned test repositories:

```sh
scripts/package-install-smoke.sh --apt-repo dist/apt-repo --apt-trusted --version 0.1.0 --duration 10m --yes
```

To generate and optionally sign a release checksum manifest:

```sh
scripts/release-manifest.sh --dir dist
scripts/release-manifest.sh --dir dist --sign
```

To generate the dependency/license inventory:

```sh
scripts/dependency-review.sh --out dist/dependency-review.md
```
