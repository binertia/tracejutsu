# Tracejutsu ARM Test

This is an experimental validation track for native 64-bit arm64 Linux hosts.
It is not required for the current amd64 deployment path, and it should not
block multi-kernel/container stress testing on amd64.

The goal is to validate that the arm64 eBPF ABI constants and shared collectors
work on real hardware. Use a disposable VPS and destroy it after collecting the
results.

## VPS Requirements

- Native `aarch64`/arm64 VM, not an LXC/container VPS.
- Debian 12/13 or Ubuntu 24.04/26.04 with systemd.
- Root or sudo access.
- 2 vCPU, 2-4 GB RAM, and 20 GB disk are enough.
- SSH only; do not run production workload during validation.

Reasonable provider families include Hetzner CAX, OCI Ampere, and AWS Graviton.

## Setup

Confirm the host is native arm64:

```sh
uname -m
uname -r
systemctl --version
```

Expected architecture:

```text
aarch64
```

Install basic build dependencies:

```sh
sudo apt-get update
sudo apt-get install -y git curl ca-certificates build-essential pkg-config sqlite3
```

Install Go `1.26.4` or newer if it is not already available:

```sh
go version
```

If needed:

```sh
curl -fsSLO https://go.dev/dl/go1.26.4.linux-arm64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.26.4.linux-arm64.tar.gz
export PATH=/usr/local/go/bin:$PATH
go version
```

Copy this repository to the VPS with your preferred method. If you only need
validation, `rsync` or `scp` without `.git` is enough.

## Validation

From the repository root on the VPS:

```sh
GOCACHE=/tmp/tracejutsu-gocache go test ./...
GOCACHE=/tmp/tracejutsu-gocache go vet ./...
GOCACHE=/tmp/tracejutsu-gocache go test -tags=ebpf_smoke ./internal/ebpf -run '^$'
```

Run the root eBPF smoke suite:

```sh
sudo env \
  GOCACHE=/tmp/tracejutsu-gocache \
  GOMODCACHE="$(go env GOMODCACHE)" \
  "$(command -v go)" test -tags=ebpf_smoke ./internal/ebpf \
  -run 'Test(Execve|Connect|FileWrite|Chmod|SensitiveRead|FileLifecycle|PrivilegeChange|NamespaceChange|ProcessAccess|NetworkServer|KernelTamper)CollectorSmoke' -v
```

Run the transient systemd smoke helper:

```sh
scripts/systemd-smoke.sh --yes
```

Run the passive stress helper:

```sh
scripts/systemd-stress.sh --duration 30m --stats-interval 1m --yes
```

## Pass Criteria

- Root smoke passes the default collectors and behavior-core collectors.
- Systemd smoke exits successfully.
- Stress exits successfully.
- Final stats show:
  - `ring_dropped=0`
  - `correlation_dropped=0`
  - `persist_dropped=0`
  - `incident_persist_dropped=0`
- Per-collector drop counters are zero.
- CPU and memory are reasonable for the VPS size.

If the narrow capability set fails, rerun smoke with the documented fallback
capabilities from `docs/INSTALL.md`, then repeat stress with the same set.

## Output To Keep

Send back only:

- Distro/version, kernel, and `uname -m`.
- Root smoke PASS/FAIL.
- Systemd smoke PASS/FAIL.
- Final stress `runtime stats` line.
- Stress CPU time and memory peak.
- If any drop counter is nonzero, include `collector_ring_dropped` and
  `event-summary` output for `file_write`.

## Cleanup

After inspection:

```sh
sudo rm -rf /var/lib/tracejutsu-smoke-* /var/lib/tracejutsu-stress-*
rm -f bin/tracejutsu-smoke-* bin/tracejutsu-stress-*
```

Destroy the VPS when finished.

## Boundaries

- This validates native 64-bit arm64 only.
- The 32-bit compat syscall ABI is not implemented.
- Do not install or enable the permanent service during this experiment.
