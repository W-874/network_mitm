# network_mitm: Account Link fallback v2 — HOS 23.0.1 candidate

A narrowly scoped, resource-bounded `ssl:s` Client-PKI fallback targeting **HOS 23.0.1 / Atmosphère 1.12.1 / emuMMC**. This candidate updates Atmosphere-libs to `cf48d233` and libnx to `cd824f90`; see [compatibility evidence and limits](HOS23-COMPATIBILITY.md). Account completion on HOS 23 remains unverified.

> This project does not imitate or repair a Nintendo identity. Its purpose is to let Horizon reach a third-party Nextendo/Prelude service that does not require a Nintendo client certificate when the console's existing `DeviceClientCert` registration fails.

## Verified status

Historical hardware testing on **HOS 22.5.0 / Atmosphère 1.11.2**, before this dependency update, confirmed:

- NIM (`0100000000000025`) completed the fallback successfully.
- Account (`010000000000001E`) completed the fallback successfully.
- NPNS (`010000000000002F`) completed the fallback successfully.
- Nintendo Account Link completed successfully through the configured Nextendo/Prelude environment.
- Mario Kart 8 Deluxe online play completed successfully through that environment.

**Known limitation:** deleting a user that is already linked still fails with **2002-0001**. Linked-user deletion is not supported or claimed by this release.

These historical results do not verify this new binary on HOS 22.5 or 23. The HOS 23 update repairs the old library's deterministic startup version rejection; it does not establish end-to-end account success.

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

## Installation

## 📦 [Installation guide (English)](README-TEST.en.md)

[中文安装指南](README-TEST.md) is also available.

For a new installation, download the release ZIP, drag its folders to the SD-card root, add the documented `[network_mitm]` settings, and reboot. The package creates the required Atmosphère module paths; users do not need to place its individual files manually.

The package contains only the module and public documentation. It does not include firmware, `prod.keys`, decrypted Nintendo executables, private analysis, logs, crash/fatal dumps, identity data, certificates, private keys, or user data.

## Build and review

Initialize the pinned submodules and run `bash tools/build-target.sh`; the container has networking disabled and installs the pinned libnx from source. See [BUILD-REPORT.md](BUILD-REPORT.md). `tools/test-host.sh` checks routing, fallback and the actual upstream firmware initializer with mocked platform I/O. `tools/check-binary.py` checks the NSP identity and memory budget. Packaging requires a matching clean source/build stamp.

This project is licensed under GPLv2; see [LICENSE](LICENSE).
