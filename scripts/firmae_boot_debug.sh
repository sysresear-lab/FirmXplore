#!/usr/bin/env bash
# Temporary execution lock; full firmware isolation has not been accepted.
printf '%s\n' 'UNISOLATED_FIRMWARE_EXECUTION_BLOCKED: FirmAE debug boot is disabled until syscall, filesystem, network and resource isolation is verified. Use static-only analysis.' >&2
exit 126
