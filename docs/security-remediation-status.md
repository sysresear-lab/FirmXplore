# Security remediation status

This workspace includes the reviewed security changes and their regression tests.
The review covers FXSA-001 through FXSA-016 and four follow-up risks. It does not
establish a complete sandbox for untrusted firmware.

| Status | Findings |
| --- | --- |
| Fixed and verified within the documented test scope | FXSA-001, FXSA-004, FXSA-005, FXSA-006, FXSA-010, FXSA-011, FXSA-012, FXSA-013, FXSA-014, FXSA-015, R-01, R-02 |
| Partially fixed | FXSA-002, FXSA-003, FXSA-007, FXSA-008, FXSA-009, FXSA-016, R-03 |
| Implemented, awaiting runtime verification | R-04 |

## Current behavior

- Untrusted firmware execution remains disabled. The Python entry points and
  the FirmAE boot debug script fail closed. Static inspection remains available.
- Ordinary Docker extraction and Ghidra worker execution are disabled pending
  enforceable output quotas and durable container cancellation supervision.
- External archive extractors are disabled. Supported standard-library archive
  extraction has input, metadata, member, depth and expanded-byte limits.
- Include files and exported artifacts use bounded reads from pinned handles.
  Windows runtime writes requiring POSIX directory descriptors fail closed.
- Task credentials use private storage and explicit task configuration. Legacy
  task snapshots remain quarantined. Fernet keys must use their canonical format;
  ciphertext created using the previous faulty key conversion needs a separately
  controlled migration.
- Evidence needs task and binary provenance. Older unbound evidence contracts
  are rejected; historical evidence and findings have not been rewritten.

## Validation

The final offline Windows run passed all **49 new security test methods**.
A broader focused run executed **143 methods: 131 passed, 6 failed or errored,
and 6 were skipped**. This is not an all-green suite.

The preserved failures cover the old `subprocess.run` mock seam, successful
Docker/external-extractor expectations for now-disabled operations, and legacy
evidence fixtures without provenance. The skipped tests require POSIX directory
descriptors and real no-follow/directory-swap behavior. Existing assertions were
not changed to accommodate these security changes.

A benign archive test on Python 3.10.5 confirmed failure before extraction when
the required tar data filter is unavailable. Actual firmware, QEMU, Docker,
Ghidra, model services and exploit payloads were not executed during this work.
The Java decompilation change has not been compiled or exercised with Ghidra.

Complete syscall, network, mount, privilege and resource isolation, container
cleanup supervision, dependency locking, legacy evidence compatibility and
browser rendering verification remain open work. Detailed local audit evidence
is retained separately from the published source tree.
