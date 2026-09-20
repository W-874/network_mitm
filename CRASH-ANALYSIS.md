# AM startup fatal: matching firmware analysis and resource-v3 repair

## Exact binary match

The user supplied Firmware/*.nca and prod.keys for local read-only analysis. hactool identified AM's Program NCA as191d2cf27011b5a15f30b8c51497d0ba.nca, ProgramID0100000000000023. Its decrypted main has exactly the crash report Build ID:

`93C0B7CC723C922159DD6E1FF4BD2C7C1E08E736000000000000000000000000`

Keys and decrypted firmware remain outside the Git/source/package tree. They are not part of the deliverables. No firmware is patched.

## What the crash actually reports

AM constructs ProgramID0100000000000035 in x2 at0x7DC04/0x7DC0C, then calls0x7DD78 at0x7DC20. The constructor calls0x77428 at0x7DE00; it checks the returned w0 at0x7DE08 and calls the fatal-result handler at0x7DE28 when nonzero. The resulting saved return address0x7DE2C matches the crash stack. The matching stack also includes0x7DC24 and0x91144.

Inside0x77428, call0xEA018 invokes the application-manager proxy vtable slot0x2C8. Following the service getter and factory:

- Getter proxy vtable0x1BF690, slot0x58 →0xEC3D4 →0xF43E8.
- The getter's IPC command at0xF4430 is0x1F3C (7996), GetApplicationManagerInterface.
- Its returned proxy vtable0x1BFE18, slot0x2C8 →0xF4A14.
- At0xF4A18 the command is0x12E (302). The sender0xD3EBC serializes this command and the input u64 ProgramID.
- The Result is propagated back to the constructor; the supplied report records0x10801.

Thus the confirmed failure boundary is AM requesting NS command302 for program0100000000000035. Atmosphere's ncm_system_content_meta_id.hpp names that program Grc. [Switchbrew's LaunchLibraryApplet description](https://switchbrew.org/wiki/NS_services#LaunchLibraryApplet) documents command302 taking a ProgramID and launching it through the process-launch services. This identifies a process-launch failure, not SSL command8 or TLS handshake failure.

The wrapper can propagate either an IPC transport error or the service's returned Result; the report does not retain the original response needed to distinguish those. Nor does it identify which resource reservation rejected the launch. We therefore do not claim a proven specific kernel memory-allocation call. The program, command, argument, error propagation and matching fatal callsite are established from the exact binary.

## Why v1 and v2 could hit the same failure

V2 console logs prove only NIM was intercepted and Generate/Import returned success with a real PKI ID. NIM's certificate registration and AM's GRC launch are different operations. Changing client selection did not remove the module's startup reservations:

- v1 NSO BSS:11283336 bytes.
- v2 NSO BSS:11275656 bytes.
- Difference:7680 bytes, despite narrowing the client list.
- v2 retained two server managers, each0x4C6DF8 bytes, and five service workers.

This is the concrete omission in the previous delivery: selection was narrowed while the large always-resident pools remained. Compilation and mock PKI tests never exercised Horizon's shared boot-time resource limits.

GRC's supplied Program NCA is9f3949ad0c404f06e5625113e35f7317.nca. Its text/rodata/data/BSS total about7MiB before further runtime allocations. Its NPDM uses pool_partition2. A large extra resident sysmodule can reduce the headroom available to process startup. This supports fixing our resource footprint, but does not measure the console's exact remaining budget or exclude other installed-module pressure.

## The actual repair

- Register only ssl:s; mitm.lst contains only ssl:s. Ordinary ssl has no reserved future MITM or registered port in this build.
- One ServerManager,16 sessions,16 domains,256 domain objects, sized for the observed single NIM experiment. This is a deliberate concurrent-capacity limit, not a universal all-program build.
- Keep the original0x10000-byte pointer buffer per session. Atmosphere-libs validates that it is at least as large as the original Service's reported pointer buffer; arbitrarily reducing it could introduce a new abort.
- Two service workers instead of five. If the optional worker cannot be created, record the Result and continue with the main worker.
- Remove unused timeInitialize/timeExit; metadata timestamps use system ticks, and PCAP date generation is disabled.
- Reject legacy broad mode; targeted=false accepts no clients. The exact allowlist and type1/original0x167B fallback gate remain.
- Read-only resource snapshots before serving, on acceptance, and before/after PKI. Log current/limit/remaining for the module's resource group. Close the temporary resource handle; never alter resource limits. Logging/query failures do not change SSL Results.

The first revised binary reduces NSO BSS from about10.75MiB to2.13MiB, recovering over8.6MiB. Final exact sizes/hashes are recorded in MEMORY-VERIFICATION.json. tools/check-binary.py enforces BSS below3MiB, at least8MiB saved against v2, correct NPDM identity and ssl:s-only startup declaration. A compile-time assertion limits the manager structure to1152KiB.

PKI transport, parameter ABI, real-ID return, key erasure and RemoveClientPki behavior are preserved. No AM/GRC patch, fake success, service quota increase, CA change, identity change or DNS change is made.

## Remaining runtime boundary

Cross-build, policy/failure tests, sanitizers and binary resource checks can verify this repair's implementation, not boot the user's console. The exact AM failure boundary is now known; the specific exhausted resource and whether this recovered headroom fully resolves it still require runtime confirmation. The added counters are intended to make that confirmation informative without restoring all-system interception. If it fails, inspect the new counters and actual build, rather than reinstalling old tracers or modifying AM to ignore the error.
