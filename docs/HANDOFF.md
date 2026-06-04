# Runtime Guard Handoff

Updated: 2026-06-04

## Current State

Runtime Guard is **100% complete for the planned MVP**. The fake-event
pipeline is runnable without root, deterministic detection and compression are
implemented, SQLite persistence is hardened, Linux amd64/native-arm64 eBPF
collectors are present, the live event path uses a bounded async persistence
queue, and the local LLM client is wired through the CLI. Live service runs
expose tunable collector-to-analyzer, async persistence queue, async persistence
batch, per-collector eBPF ring-buffer sizes, and explicit collector selection
for isolating high-volume sources.
The async event and incident persistence queues apply bounded save timeouts and
transition to a closed/drop state on the first persistence error.
Basic packaging assets are present for local service deployment: an install
guide and a conservative systemd unit that stores data under
`/var/lib/runtime-guard`, suppresses per-event JSON with `--quiet-events`, and
prints periodic stats every minute.
The service unit was further hardened with device isolation, native syscall ABI
restriction, namespace creation blocking, hostname protection,
writable-executable memory denial, and IPC cleanup.

Root-only eBPF smoke tests passed on a capable Linux amd64 host on 2026-06-03,
including after connect, file-write, and chmod syscall-exit correlation was
added. A follow-up root-only eBPF smoke pass was reported on 2026-06-04 after
runtime-guard self file writes were excluded. IPv4 and IPv6 connect smoke
subtests also passed after IPv6 sockaddr capture and connect syscall-exit
outcome handling were added.
An actual local `llama-server` report also completed successfully after JSON
Schema output enforcement was added: the response decoded, persisted, and
rendered through `runtime-guard show`.
A transient systemd sandbox smoke test passed on Debian on 2026-06-03 after the
additional sandbox directives were added. After async SQLite batch persistence
was added, a repeat short run processed about 51k normalized events with zero
ring-buffer drops, zero syscall-correlation drops, and zero persistence drops.
After runtime-guard self file writes were excluded at the eBPF entry point, a
10-minute plugged-in idle all-collector stress run on Debian processed 8,742
normalized events with zero ring-buffer, syscall-correlation, and persistence
drops. That run consumed 5.747s CPU and peaked at 90.1M memory.
A follow-up 10-minute plugged-in light desktop run with browser activity, nvim,
tmux, and a one-shot `xclip` pipeline processed 24,244 normalized events with
zero ring-buffer, syscall-correlation, and persistence drops. That run consumed
70.687s CPU and peaked at 122.8M memory.
A 30-minute plugged-in normal-use stress run then completed with zero
ring-buffer, syscall-correlation, and persistence drops. It ran for 30m5.188s,
consumed 4m20.815s CPU, and peaked at 162.5M memory.
On 2026-06-04, the transient systemd smoke helper and a 30-minute all-collector
stress run also passed with the narrower capability set
`CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE`. The 30-minute run processed 19,744
normalized events, produced one deterministic incident from local build activity,
and ended with zero ring-buffer, syscall-correlation, event-persistence, and
incident-persistence drops. It consumed 3m14.901s CPU and peaked at 117.2M
memory.
Later on 2026-06-04, the full non-root release gate passed on bare-metal
Debian 13 (trixie), kernel `6.12.90+deb13.1-amd64`, systemd 257, cgroup v2,
`x86_64`, with `govulncheck` reporting no vulnerabilities. The same host then
passed transient systemd smoke and a 30-minute all-collector stress run with the
packaged narrow capability set `CAP_BPF CAP_PERFMON CAP_SYS_RESOURCE`. The
stress run processed 193,737 normalized events, grouped 7,177 candidates, and
ended with zero ring-buffer, syscall-correlation, event-persistence, and
incident-persistence drops. Per-collector ring-buffer and correlation drops
were also zero for `execve`, `connect`, `file_write`, and `chmod`. It ran for
30m5.283s, consumed 5m17.918s CPU, and peaked at 246.6M memory.
External x86_64 VPS validation then covered Debian Bookworm, Ubuntu 22.04 LTS,
and Ubuntu 24.04 LTS on Vultr VMs. Debian Bookworm completed a 30-minute
systemd stress run with 151 normalized events, one persisted incident, and zero
ring-buffer, syscall-correlation, event-persistence, and incident-persistence
drops. Ubuntu 24.04 completed the Debian package lifecycle smoke with 324
normalized events, one persisted incident, clean package service stop/removal,
and zero required drops. Ubuntu 22.04 completed the same package lifecycle smoke
after the journal timestamp compatibility fix with 72 normalized events, clean
package service stop/removal, and zero required drops. These VPS runs were very
idle, so they validate package/systemd/capability compatibility more than
sustained workload behavior.
Native arm64 support has compile coverage and a separate experimental VPS
runbook in [`ARM_TEST.md`](ARM_TEST.md). Real arm64 smoke/stress validation is
not blocking the next amd64 hardening task.

Recent signed production-hardening commits after `origin/main`:

- `2bc4c12` makes Debian package maintainer metadata configurable.
- `48faeab` adds the combined release checksum manifest and optional detached
  GPG signing workflow.
- `0099cee` adds the fresh-host Debian/Ubuntu package install smoke helper.
- `7bb1f7e` hardens release artifact verification and repeatable build
  metadata/timestamps.
- `60dd26d` adds the Debian package builder.
- `d05ef5e` adds database operations stats.
- `6ecf2ff` adds the dependency/license review gate.
- `0e65696` adds versioned release artifact builds.
- `7b64d56` adds the CI release gate.
- `7d7e3cd` documents the separate arm64 VPS validation experiment.
- `43f081c` adds the multi-host stress validation workflow.
- `b0688ac` checks sudo access before building systemd test artifacts.
- `8c711d4` adds saved-log stress validation summarization.
- `9473509` makes systemd smoke/stress helpers fail closed on missing or
  nonzero validation drop counters.
The release helpers now cover fresh-host package lifecycle validation, combined
checksum manifest generation, optional armored detached GPG signing, and
configurable Debian maintainer metadata.

The current handoff target is a production/distribution-grade release. The
approximate readiness is:

- MVP feature surface: **100% complete**.
- Personal Debian amd64 install readiness: **93-96% complete**.
- Debian/Ubuntu amd64 production release: **82-87% complete**.
- Broad production/distribution-grade release: **70-75% complete**.
- Multi-distro amd64 plus production arm64 release: **60-65% complete**.

The remaining percentage is mostly release engineering and validation, not core
MVP functionality.

## Remaining Production Work

Before calling this distribution-grade, finish these tracks:

- Repeat the multi-host validation matrix in [`STRESS_VALIDATION.md`](STRESS_VALIDATION.md)
  under a busier normal workload on at least one Debian/Ubuntu VPS, because the
  first external VPS passes were mostly idle.
- Validate one container-host or stricter kernel/procfs environment.
- Preserve full fresh-host package lifecycle logs for Debian Bookworm,
  Ubuntu 22.04, and Ubuntu 24.04, including host fingerprint, release gate,
  root smoke, systemd smoke/stress, and package smoke outputs.
- Extend release artifacts beyond the initial tarball and Debian package
  builders if `.rpm` is required. The current builders honor
  `SOURCE_DATE_EPOCH` for repeatable build metadata and archive/package
  timestamps, and `scripts/release-manifest.sh --sign` can produce a detached
  signature for the combined checksum manifest.
- Expand release automation beyond the initial CI gate if publishing packages
  requires multiple architectures or package formats.
- Validate the operational policy in [`OPERATIONS.md`](OPERATIONS.md) under an
  installed service on each release target.
- Decide the release claim for arm64. Keep it experimental unless a native
  arm64 host completes the smoke/stress runbook in [`ARM_TEST.md`](ARM_TEST.md).
- Review `scripts/dependency-review.sh --out dist/dependency-review.md` output
  before publishing packages for other users.
- Set a real Debian package maintainer with `scripts/build-deb.sh --maintainer`
  or `RUNTIME_GUARD_PACKAGE_MAINTAINER` before publishing a `.deb`.

## Implemented MVP Surface

The current pipeline is:

```text
eBPF raw tracepoints
  -> normalized events
  -> bounded process-tree grouping
  -> deterministic rules and additive score
  -> compressed incident timeline
  -> SQLite storage
  -> optional local LLM explanation
  -> terminal report
```

Implemented live Linux amd64/native-arm64 collectors:

- `execve`
- IPv4 and IPv6 `connect`
- path-backed `write`, `writev`, `pwrite64`, `pwritev`, and `pwritev2`
- `chmod`, `fchmod`, `fchmodat`, and `fchmodat2` where exposed by the target
  syscall ABI. On arm64, direct `chmod` libc calls are captured through
  `fchmodat`/`fchmodat2`.

Connect, file write, and chmod probes correlate syscall entry and exit with
bounded in-kernel maps. Emitted records include the syscall return value and
errno. File write and chmod report `success` or `failed`; connect reports
`success`, `in_progress`, or `failed` because non-blocking clients often return
`EINPROGRESS`. A requested chmod execute bit does not prove that the bit was
newly added.

Implemented deterministic rules:

- `web_process_spawned_shell`
- `shell_downloaded_file`
- `tmp_file_made_executable`
- `recently_downloaded_binary_executed`
- `downloaded_binary_connected_outbound`
- `suspicious_reverse_shell_pattern`
- `package_manager_spawned_shell`
- `sensitive_file_access`
- `crypto_miner_process_name`
- `unexpected_network_tool_execution`

## Important Boundaries

- The LLM is not the first security boundary. Rules detect, compression
  explains, and the LLM summarizes.
- The LLM client receives compressed incident JSON only, never raw event rows.
- LLM endpoints are loopback-only by default. Remote endpoints require
  `--allow-remote-endpoint`.
- HTTP redirects are refused, loopback proxy use is bypassed, request timeouts
  are enforced, responses are size-limited, and strict JSON is required.
- llama-server receives a JSON Schema-constrained response format. The client
  still rejects malformed or schema-invalid reports instead of coercing them.
  Endpoint validation rejects credentials, query strings, fragments, missing
  hosts, unsupported schemes, and non-loopback endpoints without opt-in.
- New SQLite files are created with `0600`. Existing DB paths must be private
  regular files and cannot be symlinks. The immediate parent directory must be
  owned by the running UID and cannot permit group or other writes.
- Terminal output strips control and bidirectional formatting characters.
- Redaction covers common credential carriers including authorization headers,
  bearer tokens, API/access keys, cookies, sessions, private-key markers, and
  credential-bearing URL parameters before storage, prompts, and reports.
- Grouping retains at most 4096 events per active candidate and 65536 events
  globally. Dropped older history is reported in the incident JSON and CLI.
- Incident storage upserts its supporting evidence rows and incident links in
  one transaction, independent of async event-queue timing.
- Async event and incident persistence use a default 10-second bounded save
  timeout. SQLite event persistence is batched when possible, while persistence
  errors are still surfaced through queue error channels and future enqueue
  attempts are dropped instead of being buffered without a worker. Failed and
  buffered-but-unpersisted records are counted as dropped.
- The live CLI reports normalized, grouped, analyzed, incident, kernel
  ring-buffer-drop, syscall-correlation-drop, event-persistence, and
  incident-persistence counters every 10 seconds by default and at shutdown. It
  also reports per-collector ring-buffer and syscall-correlation drop
  breakdowns for tuning.
- `runtime-guard event-summary --type file_write` summarizes stored event
  volume by process/executable and file path so stress databases can identify
  high-volume file-write sources without manual SQLite queries.
- `runtime-guard db-stats` reports SQLite table counts, page/freelist stats,
  journal mode, and database/WAL/SHM file sizes for operations and retention
  planning.
- `runtime-guard run --event-buffer`, `--persist-buffer`,
  `--persist-batch-size`, and `--ring-buffer-size` tune burst capacity.
  `--collectors` narrows live collection to a comma-separated subset of
  `execve`, `connect`, `file_write`, and `chmod` for stress isolation or
  targeted deployments. `--file-write-min-bytes` can apply a kernel-side byte
  floor to file-write events before they enter the ring buffer. The packaged
  service uses 16384 event and persistence queue slots, 512 events per
  persistence transaction, 8 MiB per collector ring buffer, all collectors, and
  no file-write byte floor by default.
- Live runs exclude the runtime-guard process PID from file-write capture at
  the eBPF entry point. This prevents SQLite persistence writes from feeding
  back into the file-write collector and saturating the ring buffer.
- `runtime-guard run --quiet-events` suppresses per-event JSON for service-style
  operation while still printing incidents and periodic stats.
- `runtime-guard run --stats-interval` controls periodic runtime stats; `0`
  disables periodic stats while preserving final shutdown stats.
- The transient systemd smoke and stress helpers accept `--capabilities` so a
  broader compatibility `CapabilityBoundingSet` can be validated on hosts where
  the packaged narrow set fails smoke or stress.
- The transient systemd smoke and stress helpers exit nonzero when the
  transient unit fails, final runtime stats are missing, or required drop
  counters are nonzero. Saved helper logs can be summarized later with
  `scripts/validation-summary.sh`.
- The MVP never automatically kills, blocks, or remediates processes.

## Known Limitations

- Queued incident persistence avoids blocking live ingestion on incident SQLite
  writes, but a full or failed incident queue can still drop incident database
  writes. Watch `incident_persist_dropped` in runtime stats.
- Container fields are populated best-effort from procfs cgroup and container
  hostname data when available. This is a bounded PID/start-time cache; the
  hostname is not guaranteed to match the container-runtime display name.
- The eBPF smoke suite covers local loopback behavior only. Broader stress
  testing across kernel versions, containers, and network namespaces remains.
- Arm64 support targets native 64-bit processes. The 32-bit compat syscall ABI
  has not been implemented. Hardware validation is tracked separately as an
  experiment in [`ARM_TEST.md`](ARM_TEST.md).
- Earlier transient systemd stress runs reported high ring-buffer drops before
  the live path was tuned. A 30-minute Debian run processed about 3.6M
  normalized events with no persistence or correlation drops, but still had
  about 31.5M aggregate ring-buffer drops and a 3.5G memory peak. Per-collector
  drop breakdowns isolated the issue to `file_write`, and event summaries showed
  the dominant source was runtime-guard writing its own SQLite WAL/database.
  After self-PID exclusion, plugged-in idle, light desktop, and 30-minute
  normal-use all-collector stress runs completed with zero ring-buffer,
  syscall-correlation, and persistence drops. Broader stress testing across
  heavier workloads, kernel versions, containers, and network namespaces
  remains.
- `runtime-guard show` appends an existing stored LLM analysis after the
  deterministic incident evidence when one is available.

## Validation

Use a writable Go cache in this environment:

```sh
scripts/release-check.sh
```

The release gate above runs the non-root checks below:

```sh
GOCACHE=/tmp/runtime-guard-gocache \
GOMODCACHE=/tmp/runtime-guard-gomodcache \
go test ./...

GOCACHE=/tmp/runtime-guard-gocache \
GOMODCACHE=/tmp/runtime-guard-gomodcache \
go vet ./...

GOCACHE=/tmp/runtime-guard-gocache \
GOMODCACHE=/tmp/runtime-guard-gomodcache \
go test -race ./...

GOCACHE=/tmp/runtime-guard-gocache \
GOMODCACHE=/tmp/runtime-guard-gomodcache \
go test -tags=ebpf_smoke ./internal/ebpf -run '^$'

GOCACHE=/tmp/runtime-guard-gocache \
GOMODCACHE=/tmp/runtime-guard-gomodcache \
go run golang.org/x/vuln/cmd/govulncheck@latest ./...

scripts/dependency-review.sh --out /tmp/runtime-guard-dependency-review.md
```

All commands above passed on 2026-06-04 after the validation helper hardening
was added. The latest release gate also passed on bare-metal Debian 13 after
release manifest and Debian maintainer hardening; `govulncheck` reported no
vulnerabilities. The tagged smoke command verifies compilation only. Root smoke
tests also passed on a BPF-capable Linux amd64 host on 2026-06-03 after the
shared eBPF reader shutdown helper was added, including the connect syscall-exit
correlation path:

```sh
sudo go test -tags=ebpf_smoke ./internal/ebpf \
  -run 'Test(Execve|Connect|FileWrite|Chmod)CollectorSmoke'
```

The latest focused connect smoke validation passed with both IPv4 and IPv6:

```sh
sudo env \
  GOCACHE=/tmp/runtime-guard-gocache \
  GOMODCACHE="$(go env GOMODCACHE)" \
  "$(command -v go)" test -tags=ebpf_smoke ./internal/ebpf \
  -run 'TestConnectCollectorSmoke' -v
```

The current systemd sandbox smoke helper also passed on 2026-06-04 on
bare-metal Debian 13 with the packaged narrow capability set:

```sh
scripts/systemd-smoke.sh
```

The latest short run processed 1,225 normalized events and ended with:

```text
ring_dropped=0 correlation_dropped=0 persist_dropped=0 incident_persist_dropped=0
collector_ring_dropped=execve:0,connect:0,file_write:0,chmod:0
collector_correlation_dropped=execve:0,connect:0,file_write:0,chmod:0
```

Run the non-root fake pipeline:

```sh
mkdir -p "$HOME/.local/state/runtime-guard"
chmod 700 "$HOME/.local/state/runtime-guard"
DB="$HOME/.local/state/runtime-guard/runtime-guard.db"
go run ./cmd/runtime-guard demo --db "$DB"
go run ./cmd/runtime-guard show --db "$DB" inc-evt-001
```

Run local LLM analysis:

```sh
llama-server --model /path/to/model.gguf --port 8080
go run ./cmd/runtime-guard llm --db "$DB" inc-evt-001
go run ./cmd/runtime-guard show --db "$DB" inc-evt-001
```

## Recommended Next Task

1. Push or otherwise back up the signed commits after `origin/main`.
2. Run `scripts/build-release.sh --version v0.1.0` and
   `scripts/build-deb.sh --version v0.1.0` once on the release host, then
   inspect the generated artifacts and `runtime-guard version` output.
3. Generate `scripts/dependency-review.sh --out dist/dependency-review.md` and
   review the dependency/license inventory.
4. Generate `scripts/release-manifest.sh --dir dist --sign` and verify the
   published `SHA256SUMS` plus `SHA256SUMS.asc` on a clean machine.
5. Save the full Debian Bookworm, Ubuntu 22.04, and Ubuntu 24.04 VPS logs under
   a local validation directory, then bundle them with
   `scripts/validation-bundle.sh` and copy the final summaries into release
   notes.
6. Repeat `scripts/systemd-stress.sh --duration 30m --stats-interval 1m --yes`
   on at least one VPS while applying light normal activity, then summarize it
   with `scripts/validation-summary.sh`.
7. Validate one container host or stricter kernel/procfs environment.
8. Save every full helper output and summarize it with
   `scripts/validation-summary.sh`.
9. Start `.rpm` or broader package-format work only after the busier VPS pass
   and container/strict-host pass both have zero required drops.

## File Map

```text
cmd/runtime-guard/        CLI routing and live loop
internal/ebpf/            Linux amd64/native-arm64 raw-tracepoint collectors
internal/events/          normalized event model and grouping
internal/pipeline/        grouper -> detector -> compressor orchestration
internal/detect/          deterministic rules and scoring
internal/compress/        compact incident timeline and summary
internal/store/           SQLite persistence, schema, and upgrades
internal/llm/             local HTTP client, prompt, strict report contract
internal/report/          terminal-safe rendering
internal/persistqueue/    bounded async event persistence queue
testdata/events/          fake normalized event fixtures
docs/                     plan and this handoff
docs/ARM_TEST.md          native arm64 VPS experiment
docs/OPERATIONS.md        database growth, backup, compaction, and log guidance
docs/STRESS_VALIDATION.md multi-host stress validation matrix
packaging/systemd/        local systemd service template
```
