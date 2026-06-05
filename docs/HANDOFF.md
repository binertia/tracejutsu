# Tracejutsu Handoff

Updated: 2026-06-05

## Current State

Tracejutsu is **100% complete for the planned MVP**. The fake-event
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
`/var/lib/tracejutsu`, suppresses per-event JSON with `--quiet-events`, and
prints periodic stats every minute.
The service unit was further hardened with device isolation, native syscall ABI
restriction, namespace creation blocking, hostname protection,
writable-executable memory denial, and IPC cleanup.

Root-only eBPF smoke tests passed on a capable Linux amd64 host on 2026-06-03,
including after connect, file-write, and chmod syscall-exit correlation was
added. A follow-up root-only eBPF smoke pass was reported on 2026-06-04 after
tracejutsu self file writes were excluded. IPv4 and IPv6 connect smoke
subtests also passed after IPv6 sockaddr capture and connect syscall-exit
outcome handling were added.
An actual local `llama-server` report also completed successfully after JSON
Schema output enforcement was added: the response decoded, persisted, and
rendered through `tracejutsu show`.
A transient systemd sandbox smoke test passed on Debian on 2026-06-03 after the
additional sandbox directives were added. After async SQLite batch persistence
was added, a repeat short run processed about 51k normalized events with zero
ring-buffer drops, zero syscall-correlation drops, and zero persistence drops.
After tracejutsu self file writes were excluded at the eBPF entry point, a
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
On 2026-06-05, a fresh Ubuntu 22.04.5 LTS x86_64 VPS on kernel
`5.15.0-179-generic`, systemd 249, cgroup v2, virtualization reported as
`microsoft`, and no container completed follow-up transient systemd smoke,
30-minute systemd stress, and Debian package lifecycle smoke. The stress run
processed 18,366 normalized events, grouped and analyzed 10,243 candidates,
persisted 282 incidents, and ended with zero ring-buffer,
syscall-correlation, event-persistence, and incident-persistence drops. All
per-collector ring-buffer and syscall-correlation drops were also zero. The
package lifecycle smoke processed 168 normalized events and removed the package
cleanly with zero required drops.
Also on 2026-06-05, a Debian 13 Docker/containerd host completed the
container-host validation path. A 12-minute all-collector systemd stress run
with the packaged narrow capability set processed 3,959 normalized events,
grouped and analyzed 1,052 candidates, persisted 242 expected low-severity
incidents from the deliberate container workload, and ended with zero
ring-buffer, syscall-correlation, event-persistence, and incident-persistence
drops. Per-collector ring-buffer and syscall-correlation drops were zero for
all collectors. The run consumed 59.511s CPU and peaked at 89.6M memory.
Stored container workload events included non-empty container metadata, for
example a 64-character `container_id`, `container_name=8f4d99a9e4d1`,
`parent_process_name=containerd-shim`, and container process paths such as
`/bin/sh`, `/bin/mkdir`, and `/bin/chmod`.
Also on 2026-06-05, a fresh Debian 12 Bookworm bare-metal VPS completed the
release artifact validation path on host `guest`, kernel
`6.1.0-49-amd64`, systemd `252.39-1~deb12u2`, cgroup v2, `x86_64`, Go
`1.26.4`, no virtualization detected, and no container environment detected.
Transient systemd smoke processed 10 normalized events, grouped and analyzed 4
candidates, and ended with zero required drops. The smoke run completed in
8.111s and consumed 171ms CPU. A 30-minute all-collector systemd stress run
processed 70 normalized events, grouped and analyzed 25 candidates, persisted 2
incidents, and ended with zero ring-buffer, syscall-correlation,
event-persistence, and incident-persistence drops. The stress run consumed
932ms CPU. The actual release Debian package installed from
`dist/tracejutsu_0.1.0_amd64.deb` then completed package lifecycle smoke,
processed 57 normalized events, grouped and analyzed 44 candidates, removed the
package cleanly, and ended with zero required drops.
A follow-up Debian 12 release package smoke on the same host with
`--keep-installed` also passed after purging old package config and state. The
helper verified `tracejutsu_0.1.0_amd64.deb: OK`, processed 99 normalized
events, grouped and analyzed 43 candidates, removed no package by request, and
ended with zero ring-buffer, syscall-correlation, event-persistence, and
incident-persistence drops. After manually starting the installed service, the
operations validation helper passed on the same host: `tracejutsu.service` was
active, the package was not enabled for boot, `/var/lib/tracejutsu` was `0700`,
`tracejutsu.db` was `0600`, SQLite reported `journal_mode: wal`, `db-stats`
reported 142 stored events and 0 incidents, recent runtime stats were present
with zero required drops, and the online SQLite backup integrity check returned
`ok` for `/var/backups/tracejutsu/tracejutsu-20260605T130057Z.db`.
Native arm64 support has compile coverage and a separate experimental VPS
runbook in [`ARM_TEST.md`](ARM_TEST.md). Real arm64 smoke/stress validation is
not blocking the next amd64 hardening task.

Recent signed production-hardening commits after `origin/main`:

- `f7ad5a3` records the Debian 12 keep-installed release package smoke pass.
- `685e1fa` adds installed-service operations validation for db-stats, WAL
  mode, runtime stats, and online SQLite backup checks.
- `85c787e` adds a fresh-host RPM install smoke helper.
- `776e180` adds experimental RPM package building and manifest support.
- `4e835b0` lets the package install smoke helper validate an existing release
  `.deb` and its checksum before installing it.
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
- `7d7e3cd` documents the separate arm64 VPS validation experiment.
- `43f081c` adds the multi-host stress validation workflow.
- `b0688ac` checks sudo access before building systemd test artifacts.
- `8c711d4` adds saved-log stress validation summarization.
- `9473509` makes systemd smoke/stress helpers fail closed on missing or
  nonzero validation drop counters.
The release helpers now cover fresh-host package lifecycle validation, combined
checksum manifest generation, optional armored detached GPG signing, and
configurable Debian maintainer metadata. A container-host workload helper is
also present and has validated Docker/containerd metadata capture on Debian 13;
it runs an unprivileged Docker or Podman container without host mounts or host
networking while the normal systemd stress helper observes the host.
An experimental RPM builder is also present. It mirrors the Debian package
layout, requires `rpmbuild` only when invoked, writes a per-package checksum,
and is included in the release manifest when RPM artifacts exist. A matching
RPM install-smoke helper is present for fresh Fedora/RHEL-compatible validation
hosts. Real RPM build/install smoke validation is still pending.
An operations validation helper is also present for installed service hosts; it
checks service state, SQLite `db-stats`, WAL mode, file-write summary, incident
listing, recent runtime stats, and an online SQLite backup without stopping the
service.
A release bundle helper is also present. It builds artifacts into an empty
directory, refuses placeholder package metadata by default, writes
`dependency-review.md`, regenerates `SHA256SUMS`, and can produce a detached
manifest signature.
An experimental static APT repository helper is also present. It builds
`pool/` and `dists/` metadata from release `.deb` files and can sign
`InRelease` plus `Release.gpg`. The package install smoke helper can now
configure a temporary APT source with `--apt-repo` and validate installation
through that repository; a fresh-host run of that path is still pending.
For disposable Debian/Ubuntu validation hosts, `./test.sh --yes` now bootstraps
apt dependencies, ensures the pinned Go toolchain, runs release/smoke/stress
checks, and validates direct `.deb` plus local APT repository installation in
one command.

The current handoff target is a production/distribution-grade release. The
approximate readiness is:

- MVP feature surface: **100% complete**.
- Personal Debian amd64 install readiness: **96-98% complete**.
- Debian/Ubuntu amd64 production release: **90-94% complete**.
- Broad production/distribution-grade release: **79-84% complete**.
- Multi-distro amd64 plus production arm64 release: **65-70% complete**.

The remaining percentage is mostly release engineering and validation, not core
MVP functionality.

## Remaining Production Work

Before calling this distribution-grade, finish these tracks:

- Keep the current Docker/containerd evidence bundle and use the summarized
  Debian 12, Ubuntu 22.04, Debian 13, and container-host results already
  recorded here for private-beta release notes. Older Debian Bookworm and
  Ubuntu 24.04 VPS full logs are useful but no longer blocking.
- Validate a stricter kernel/procfs environment if target deployments require
  capability fallback beyond the packaged narrow set. Docker/containerd host
  metadata capture is already validated on Debian 13 with
  `scripts/container-workload.sh`.
- Validate the experimental RPM builder and `scripts/rpm-install-smoke.sh` on a
  Fedora/RHEL-compatible host if RPM distribution is required. The current
  tarball, Debian package, and RPM builders honor `SOURCE_DATE_EPOCH` for build
  metadata and staged artifact timestamps where their toolchains support it,
  and `scripts/release-manifest.sh --sign` can produce a detached signature for
  the combined checksum manifest.
- Expand local release automation further only if publishing packages requires
  more package formats or a hosted package repository.
- Validate the experimental APT repository helper by publishing or copying
  `dist/apt-repo` to a fresh Debian/Ubuntu target, then running
  `scripts/package-install-smoke.sh --apt-repo ... --apt-keyring ...` for a
  signed repository or `--apt-trusted` for a local unsigned test repository.
- Repeat `scripts/ops-validation.sh --yes` under an installed service on any
  additional release target that needs its own operations evidence. Debian 12
  Bookworm has passed this check.
- Decide the release claim for arm64. Keep it experimental unless a native
  arm64 host completes the smoke/stress runbook in [`ARM_TEST.md`](ARM_TEST.md).
- Review `scripts/dependency-review.sh --out dist/dependency-review.md` output
  before publishing packages for other users.
- Set a real Debian package maintainer with `scripts/build-deb.sh --maintainer`
  or `TRACEJUTSU_PACKAGE_MAINTAINER` before publishing a `.deb`.

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
- `tracejutsu event-summary --type file_write` summarizes stored event
  volume by process/executable and file path so stress databases can identify
  high-volume file-write sources without manual SQLite queries.
- `tracejutsu db-stats` reports SQLite table counts, page/freelist stats,
  journal mode, and database/WAL/SHM file sizes for operations and retention
  planning.
- `tracejutsu run --event-buffer`, `--persist-buffer`,
  `--persist-batch-size`, and `--ring-buffer-size` tune burst capacity.
  `--collectors` narrows live collection to a comma-separated subset of
  `execve`, `connect`, `file_write`, and `chmod` for stress isolation or
  targeted deployments. `--file-write-min-bytes` can apply a kernel-side byte
  floor to file-write events before they enter the ring buffer. The packaged
  service uses 16384 event and persistence queue slots, 512 events per
  persistence transaction, 8 MiB per collector ring buffer, all collectors, and
  no file-write byte floor by default.
- Live runs exclude the tracejutsu process PID from file-write capture at
  the eBPF entry point. This prevents SQLite persistence writes from feeding
  back into the file-write collector and saturating the ring buffer.
- `tracejutsu run --quiet-events` suppresses per-event JSON for service-style
  operation while still printing incidents and periodic stats.
- `tracejutsu run --stats-interval` controls periodic runtime stats; `0`
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
  the dominant source was tracejutsu writing its own SQLite WAL/database.
  After self-PID exclusion, plugged-in idle, light desktop, and 30-minute
  normal-use all-collector stress runs completed with zero ring-buffer,
  syscall-correlation, and persistence drops. Broader stress testing across
  heavier workloads, kernel versions, containers, and network namespaces
  remains.
- `tracejutsu show` appends an existing stored LLM analysis after the
  deterministic incident evidence when one is available.

## Validation

Use a writable Go cache in this environment:

```sh
scripts/release-check.sh
```

The release gate above runs the non-root checks below:

```sh
GOCACHE=/tmp/tracejutsu-gocache \
GOMODCACHE=/tmp/tracejutsu-gomodcache \
go test ./...

GOCACHE=/tmp/tracejutsu-gocache \
GOMODCACHE=/tmp/tracejutsu-gomodcache \
go vet ./...

GOCACHE=/tmp/tracejutsu-gocache \
GOMODCACHE=/tmp/tracejutsu-gomodcache \
go test -race ./...

GOCACHE=/tmp/tracejutsu-gocache \
GOMODCACHE=/tmp/tracejutsu-gomodcache \
go test -tags=ebpf_smoke ./internal/ebpf -run '^$'

GOCACHE=/tmp/tracejutsu-gocache \
GOMODCACHE=/tmp/tracejutsu-gomodcache \
go run golang.org/x/vuln/cmd/govulncheck@latest ./...

scripts/dependency-review.sh --out /tmp/tracejutsu-dependency-review.md
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
  GOCACHE=/tmp/tracejutsu-gocache \
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
mkdir -p "$HOME/.local/state/tracejutsu"
chmod 700 "$HOME/.local/state/tracejutsu"
DB="$HOME/.local/state/tracejutsu/tracejutsu.db"
go run ./cmd/tracejutsu demo --db "$DB"
go run ./cmd/tracejutsu show --db "$DB" inc-evt-001
```

Run local LLM analysis:

```sh
llama-server --model /path/to/model.gguf --port 8080
go run ./cmd/tracejutsu llm --db "$DB" inc-evt-001
go run ./cmd/tracejutsu show --db "$DB" inc-evt-001
```

## Recommended Next Task

1. Push or otherwise back up any latest signed commits after checking
   `git status --short --branch`.
2. Run the full local release gate with vulnerability lookup:

   ```sh
   scripts/release-check.sh
   ```

3. Build the release directory with real maintainer metadata:

   ```sh
   scripts/release-bundle.sh --version v0.1.0 --maintainer "Your Name <you@example.com>" --sign
   ```

4. Inspect the generated artifacts, `tracejutsu version` output, and
   `dependency-review.md`.
5. Verify the published `SHA256SUMS` plus `SHA256SUMS.asc` on a clean machine.
6. Keep `validation-artifacts/debian-13-docker-container-host.tar.gz` as the
   container-host evidence bundle for release notes.
7. Re-run package lifecycle smoke against the actual release `.deb` on any
   release target whose full log was not preserved after the journal timestamp
   compatibility fix:

   ```sh
   scripts/package-install-smoke.sh --deb dist/tracejutsu_0.1.0_amd64.deb --duration 10m --yes
   ```
8. Start `.rpm` or broader package-format work only after evidence bundles are
   saved and any required stricter-host pass has zero required drops.

## File Map

```text
cmd/tracejutsu/        CLI routing and live loop
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
