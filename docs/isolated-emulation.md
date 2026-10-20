# Isolated firmware emulation

`isolated-qemu` runs a bounded, ephemeral Docker worker. It is the configured
default for `emulate`; the legacy direct-host backends retain their execution
lock. No environment-variable override unlocks those backends.

Build the worker from the installed dynamic base image:

```powershell
docker build -t firmxplore-isolated:latest -f docker/Dockerfile.isolated .
```

The build installs a cross-assembler in a separate build stage. The final image
contains only its fixed guest-side helper, the dynamic base and validated
kernels. Building initially requires the distribution package repositories.

The task directory must contain a regular `canonical-rootfs.tar.gz` archive
with its entries under `rootfs/`, plus the task's original `reports/analysis.json`.
The two TP-Link tasks exported on 2026-10-20 already have this archive:

```powershell
python -m fwagent.cli emulate tplink-wr841nv14-isolated-20261020 --workspace reports/tplink-20261020/isolated-artifacts --backend isolated-qemu --timeout 180
python -m fwagent.cli emulate tplink-wr940nv6-isolated-20261020 --workspace reports/tplink-20261020/isolated-artifacts --backend isolated-qemu --timeout 180
```

Results and the exact Docker commands are recorded under
`<task>/dynamic/isolated/result.json` and `logs/commands.jsonl`. The worker image,
input archive, worker source and syscall policy have recorded identities.

## Execution boundary

The supervisor snapshots the input, creates a randomly named container and
checks the daemon's actual settings before starting it. The container uses
uid/gid 65534, no capabilities, no new privileges, a read-only root and inputs,
private PID/IPC namespaces, no Docker socket, no network, no published ports,
512 MiB memory, two CPUs, 128 PIDs and quota-limited temporary filesystems.
A positive seccomp syscall list denies mounts, namespace creation and kernel
administration. Namespace flags in `clone` are denied; `clone3` returns ENOSYS
so the runtime can use the filtered older interface.

The worker tests denied mounts/user namespaces, read-only inputs, unprivileged
identity, seccomp and loopback-only networking before executing firmware.
An in-container hard timeout remains effective if the Docker client exits.
AutoRemove and a host `finally` cleanup handle normal completion and failure.
The archive extractor enforces member/expanded-byte budgets, rejects traversal
and duplicates, delays confined links, and never materializes device nodes on
the host. Guest device entries are written as initramfs metadata only.

## What the observations establish

The first check executes the firmware's actual BusyBox under the matching
MIPS little/big-endian user emulator. For legacy threading/IPC dependencies,
the worker can build an initramfs and start a Malta Linux guest with the same
firmware filesystem. Requests run inside the guest. Its virtual NIC uses QEMU
user networking with `restrict=on`; the outer container also has no network.

This is reconstructed execution. `full_system_boot=false` and
`original_vendor_boot=false` remain explicit: the vendor's SoC, flash contents,
Wi-Fi chipset and original boot sequence are not reproduced by Malta.

Repairs are recorded under `vm.runtime_repairs`. They include the generic
kernel's required NVRAM interposer, guest LAN bridge setup, Atheros device
aliases to generic compatibility devices, unavailable NAT-table handling,
guest filter-rule flushing with INPUT/OUTPUT ACCEPT, and a later HTTP-daemon
restart where required. The WR841N control message
replays only the baseline local HTTP listener configuration (`0x7ee`, UTF-8,
port 80) inferred from the firmware's own receive function. It does not modify
authentication code or HTTP handlers. These repairs limit the conclusions
that can be drawn about stock behavior, firewalling and authentication.

`emulation_level`, `kernel_boot_observed`, `vendor_binary_observed` and actual
`http_responses` distinguish binary loading, guest initialization and service
reachability. An HTTP 404 establishes a response from that specific service;
it is neither a vulnerability nor proof that the management UI works.
WR940N's original module dispatcher (`FUN_00498c3c`) can wait
`0x641 * 50 ms` (about 80 seconds) for wireless initialization before the
management HTTP setup continues. The worker allows a 95-second guest startup
window for this firmware family and a 140-second VM deadline. A 35-second
check was premature: a longer isolated trial returned HTTP 200 on both
loopback and LAN addresses without changing the wireless download behavior.
Ephemeral runs finish with state `stopped`, rather than claiming a container
continues running after cleanup.

## TP-Link observations on 2026-10-20

| Firmware | Management HTTP | Other baseline response |
| --- | --- | --- |
| TL-WR841N V14 / 220816 | Guest LAN `192.168.0.1:80`: 200 login page | Loopback port 80: 403 |
| TL-WR940N V6 / 220801 | Guest LAN and loopback port 80: 200 | UPnP port 1900 root path: 404 |

The tests use ordinary GET requests inside the guest. These observations
establish management-service execution under the recorded repairs, without
promoting static candidate Findings to confirmed vulnerabilities. The exported
results are under `reports/tplink-20261020/isolated-artifacts/`; the bilingual
reports describe the preserved initial static run and subsequent runtime work.

## Truncated kernel repair

The previous `vmlinux.mipsel.4` was 3,706,560 bytes, although its ELF LOAD segment
extended beyond that length. It could never load successfully in QEMU.
The replacement is the official FirmAE v1.0 release, 9,756,972 bytes:

- Source: https://github.com/pr0v3rbs/FirmAE_kernel-v4.1/releases/download/v1.0/vmlinux.mipsel.4
- SHA-256: `aeaa2a3cc13af5fe8f5cc4dc66c756b75051b972937862656a6e39e936da2d2f`

The Docker build checks this digest and calls `scripts/validate_kernel_elf.py`
to reject incomplete ELF program segments for both MIPS 4.1 kernels.
