# Tracejutsu Stress Validation

This is the active validation track after the MVP. The goal is to compare
Tracejutsu across real kernels, distributions, and container/network
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
If you save full helper output to a file, summarize it later with
`scripts/validation-summary.sh`.
Use `scripts/validation-bundle.sh` to package copied logs, host/repository
metadata, summaries, and checksums into one archive for release evidence.

## Baseline Commands

On each target, from the repository root:

```sh
GOCACHE=/tmp/tracejutsu-gocache go test ./...
GOCACHE=/tmp/tracejutsu-gocache go vet ./...
GOCACHE=/tmp/tracejutsu-gocache go test -tags=ebpf_smoke ./internal/ebpf -run '^$'
```

Then run root eBPF smoke:

```sh
sudo env \
  GOCACHE=/tmp/tracejutsu-gocache \
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

## Container Host Workload

On a host with Docker or Podman, run the normal host stress helper first, then
run a short unprivileged container workload in a second terminal or tmux pane.
The workload does not mount host paths, does not use host networking, drops all
container capabilities, and does not intentionally connect to external
networks. It emits exec, file-write, chmod, and local loopback connect attempts
from inside the container.

The helper does not pull images by default. Pull the image explicitly first, or
opt in with `--pull missing` if network image pulls are acceptable on the test
host:

```sh
docker pull alpine:3.20
# or:
podman pull alpine:3.20
```

Run the stress helper:

```sh
scripts/systemd-stress.sh --duration 30m --stats-interval 1m --yes \
  2>&1 | tee rg-systemd-stress-container.log
```

While stress is running, start the container workload:

```sh
scripts/container-workload.sh --duration 10m --pull never --yes \
  2>&1 | tee rg-container-workload.log
```

After stress exits, confirm the final validation summary passes and inspect the
stress database for stored events with non-empty container metadata:

```sh
sudo /var/lib/tracejutsu-stress-.../tracejutsu-stress \
  events \
  --db /var/lib/tracejutsu-stress-.../tracejutsu.db \
  --limit 100000 |
  grep -E '"container_id":"[^"]+"'
```

For a container-host pass, the stress helper must meet the normal zero-drop
criteria and at least one stored event from the workload should include a
non-empty `container_id`. `container_name` is best-effort and may be a container
hostname rather than the runtime display name.
Save the metadata sample to a supporting log before cleaning the stress state
directory:

```sh
sudo /var/lib/tracejutsu-stress-.../tracejutsu-stress \
  events \
  --db /var/lib/tracejutsu-stress-.../tracejutsu.db \
  --limit 100000 |
  grep -m 5 -E '"container_id":"[^"]+"' \
  > rg-container-metadata-sample.log
```

After transient smoke/stress pass on a fresh Debian or Ubuntu target, copy the
release `.deb` and matching `.deb.sha256` to the host, then validate the actual
Debian package lifecycle:

```sh
scripts/package-install-smoke.sh --deb dist/tracejutsu_0.1.0_amd64.deb --duration 10m --yes
```

Run package lifecycle validation inside `tmux` or another persistent session on
SSH hosts. The helper attempts cleanup on exit, termination, and hangup, but a
persistent session makes the resulting log and package state easier to audit.
Omit `--deb` only when intentionally testing a helper-built temporary package
instead of the release artifact.

On Fedora/RHEL-compatible targets where an RPM is being evaluated, run the RPM
lifecycle helper instead:

```sh
scripts/rpm-install-smoke.sh --rpm dist/tracejutsu-0.1.0-1.x86_64.rpm --duration 10m --yes
```

Save logs when comparing hosts:

```sh
scripts/systemd-stress.sh --duration 30m --stats-interval 1m --yes \
  2>&1 | tee tracejutsu-stress-hostname.log

scripts/validation-summary.sh tracejutsu-stress-hostname.log

scripts/validation-bundle.sh \
  --name ubuntu-24-vps \
  rg-host.log \
  rg-release-check.log \
  rg-root-smoke.log \
  rg-systemd-smoke.log \
  rg-systemd-stress.log \
  rg-package-smoke.log
```

For container-host runs, keep the stress log as the pass/fail input and attach
the workload log plus container metadata sample as supporting evidence:

```sh
scripts/validation-bundle.sh \
  --name debian-13-docker-container-host \
  --supporting rg-container-workload-meta.log \
  --supporting rg-container-metadata-sample.log \
  rg-systemd-stress-container-meta.log
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

The smoke and stress helpers exit nonzero when the transient unit fails, final
runtime stats are missing, or any required drop counter is nonzero. Saved logs
can be checked later with `scripts/validation-summary.sh`, which applies the
same pass/fail criteria.

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
sudo /var/lib/tracejutsu-stress-.../tracejutsu-stress \
  event-summary \
  --db /var/lib/tracejutsu-stress-.../tracejutsu.db \
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
