# network_mitm: Account Link fallback v2

A narrowly scoped, resource-bounded `ssl:s` Client-PKI fallback for **HOS 22.5.0 / Atmosphère 1.11.2 / emuMMC**, based on upstream `c15d659600760ac83151e38660c468244176c5b0` with unchanged Atmosphere-libs `d3083af1827cd6ca2a96feb9316eb85cd01bae1f`.

> This project does not imitate or repair a Nintendo identity. Its purpose is to let Horizon reach a third-party Nextendo/Prelude service that does not require a Nintendo client certificate when the console's existing `DeviceClientCert` registration fails.

## Verified status

Hardware testing in the target environment confirmed:

- NIM (`0100000000000025`) completed the fallback successfully.
- Account (`010000000000001E`) completed the fallback successfully.
- NPNS (`010000000000002F`) completed the fallback successfully.
- Nintendo Account Link completed successfully through the configured Nextendo/Prelude environment.
- Mario Kart 8 Deluxe online play completed successfully through that environment.

**Known limitation:** deleting a user that is already linked still fails with **2002-0001**. Linked-user deletion is not supported or claimed by this release.

These results apply only to the environment above. Do not infer compatibility with other HOS or Atmosphère versions.

## Exact interception boundary

The release registers **only `ssl:s`**. It does **not** register ordinary `ssl`.

Ordinary `ssl` was removed after a hardware-observed `network_mitm` `0xFFFE` panic following an ordinary-SSL `CreateContext` from systemWeb (`0100000000001042`). The final `mitm.lst` therefore contains exactly one line:

```text
ssl:s
```

The `ssl:s` allowlist contains exactly these three system Program IDs:

| Component | Program ID |
| --- | --- |
| NIM | `0100000000000025` |
| Account | `010000000000001E` |
| NPNS | `010000000000002F` |

An absent, invalid, or empty allowlist fails closed. `should_mitm_all` cannot widen this release to ordinary `ssl` or to additional clients.

## Fallback contract

For an allowlisted `ssl:s` client, the implementation:

1. forwards `RegisterInternalPki` to the original SSL service first;
2. preserves original success and every unrelated error;
3. considers fallback only for `InternalPki` **type 1** (`DeviceClientCertDefault`);
4. triggers only when the original result is exactly **`0x0000167B`**;
5. calls the original SSL service's `GeneratePrivateKeyAndCert`, then `ImportClientCertKeyPki`; and
6. returns the real SSL-service `PkiId` produced by the import.

It does not fabricate a `PkiId`, fake success, retry the damaged identity, or change `RemoveClientPki` behavior.

## Safety and non-goals

This project does **not**:

- modify, restore, copy, or export PRODINFO/PRODINFOF, CAL0, NAND, BOOT0/BOOT1, BIS, eMMC, fuses, serial data, `ssl_rsa_key`, eTicket identity, device identity, or Nintendo certificate/private-key material;
- write generated certificate or private-key material to SD, logs, or release artifacts;
- capture TLS payloads, tokens, passwords, account contents, or user data;
- change Prelude hosts, DNS, CA/trust configuration, TLS verification, routing, or endpoints;
- bypass account authentication or server authorization; or
- support testing against Nintendo production endpoints.

Use only on hardware and accounts you control, with the existing Nextendo/Prelude configuration. **Do not test this release against Nintendo production endpoints.**

## Installation and rollback

Read [README-TEST.md](README-TEST.md) before installation and keep [README-ROLLBACK.md](README-ROLLBACK.md) available. Replace both `exefs.nsp` and `mitm.lst`; do not combine this module with an older ordinary-`ssl` diagnostic package. Preserve the existing Prelude hosts and trust configuration.

The package contains only the module and public documentation. It does not include firmware, `prod.keys`, decrypted Nintendo executables, private analysis, logs, crash/fatal dumps, identity data, certificates, private keys, or user data.

## Build and review

Build using the upstream Docker recipe or the equivalent devkitPro environment documented in [BUILD-REPORT.md](BUILD-REPORT.md). `tools/test-host.sh` performs local host-side policy and orchestration checks; it does not contact Nintendo production endpoints. `tools/check-binary.py` verifies the NSP memory budget and service declaration. The generated package manifest records the exact target build and package hashes.

This project is licensed under GPLv2; see [LICENSE](LICENSE).
