# Runtime Guard Stress Validation

This is the active validation track after the MVP. The goal is to compare
Runtime Guard across real kernels, distributions, and container/network
namespace setups before treating the packaged service as broadly installable.

Arm64 hardware validation is separate and experimental. See `ARM_TEST.md`.

## Host Matrix

Start with these targets:

| Target | Purpose |
| --- | --- |
| Debian stable on a normal laptop/server | Baseline supported deployment |
| Ubuntu LTS on a VM or VPS | Common kernel/systemd variation |
| A container host with Docker, containerd, or Podman | Container metadata and namespace behavior |
| A host with stricter kernel or procfs policy | Capability fallback validation |

Record for every run:

- Distro and version.
- Kernel and architecture.
- Systemd version.
- Cgroup filesystem.
- Virtualization/container detection.
- Capability set used.
- Final `runtime stats` line.
- CPU time and memory peak from `systemd-run --wait`.

The systemd helpers print this host fingerprint and final validation summary
automatically.

## Baseline Commands

On each target, from the repository root:

```sh
GOCACHE=/tmp/runtime-guard-gocache go test ./...
GOCACHE=/tmp/runtime-guard-gocache go vet ./...
GOCACHE=/tmp/runtime-guard-gocache go test -tags=ebpf_smoke ./internal/ebpf -run '^$'
```

Then run root eBPF smoke:

```sh
sudo env \
  GOCACHE=/tmp/runtime-guard-gocache \
  GOMODCACHE="$(go env GOMODCACHE)" \
  "$(command -v go)" test -tags=ebpf_smoke ./internal/ebpf \
  -run 'Test(Execve|Connect|FileWrite|Chmod)CollectorSmoke' -v
```

Run transient systemd smoke:

```sh
scripts/systemd-smoke.sh --yes
```

Run passive stress under normal host activity:

```sh
scripts/systemd-stress.sh --duration 30m --stats-interval 1m --yes
```

## Pass Criteria

- Root smoke passes all four collectors.
- Systemd smoke exits successfully.
- Stress exits successfully.
- Final stats show:
  - `ring_dropped=0`
  - `correlation_dropped=0`
  - `persist_dropped=0`
  - `incident_persist_dropped=0`
- `collector_ring_dropped` and `collector_correlation_dropped` are zero for
  each enabled collector.
- CPU and memory are acceptable for the target class.

## If Narrow Capabilities Fail

Rerun smoke with a broader compatibility set:

```sh
scripts/systemd-smoke.sh --yes \
  --capabilities "CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE"
```

If that passes, repeat stress with the same set:

```sh
scripts/systemd-stress.sh --duration 30m --stats-interval 1m --yes \
  --capabilities "CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE"
```

Only consider a service override after both smoke and stress pass on the exact
target kernel.

## If Drops Return

Capture the final summary and run `event-summary` against the stress database:

```sh
sudo /var/lib/runtime-guard-stress-.../runtime-guard-stress \
  event-summary \
  --db /var/lib/runtime-guard-stress-.../runtime-guard.db \
  --type file_write \
  --limit 10
```

Isolate noisy collectors:

```sh
scripts/systemd-stress.sh --duration 10m --stats-interval 1m --collectors connect --yes
scripts/systemd-stress.sh --duration 10m --stats-interval 1m --collectors file_write --yes
```

If `file_write` is the source, test a host-specific byte floor:

```sh
scripts/systemd-stress.sh --duration 10m --stats-interval 1m \
  --collectors file_write \
  --file-write-min-bytes 4096 \
  --yes
```

Do not make a byte floor the default unless the target workload requires it.
Small sensitive-file edits can be missed.
