# Account Link fallback v2: Installation and controlled test

**English** · [中文安装指南](README-TEST.md)

> **Read before installation:** [README-ROLLBACK.md](README-ROLLBACK.md) · This guide is only for HOS 22.5.0 / Atmosphère 1.11.2 / emuMMC.

This package registers `ssl:s` only; ordinary `ssl` is not registered. It targets exactly NIM, Account, and NPNS, and applies the original-first fallback only to `InternalPki` type 1 when the original result is exactly `0x0000167B`. It does not change Prelude, DNS, CA, TLS verification, or device identity.

## Installation

1. Fully power off the console. Back up the existing `/atmosphere/contents/4200000000000666/`, `system_settings.ini`, and this test's logs.
2. Merge this package into the SD-card root. **Replace both `exefs.nsp` and `mitm.lst`** at `/atmosphere/contents/4200000000000666/`; keep `flags/boot2.flag`.
3. `mitm.lst` must contain exactly one line:

   ```text
   ssl:s
   ```

4. Merge only the complete `[network_mitm]` section below; do not overwrite other settings sections:

```ini
[network_mitm]
enable_ssl = u8!0x1
targeted_device_pki_mode = u8!0x1
mitm_program_ids = str!0100000000000025 010000000000001E 010000000000002F
trace_internal_pki = u8!0x1
enable_device_cert_fallback = u8!0x1
device_cert_fallback_program_ids = str!0100000000000025 010000000000001E 010000000000002F
enable_account_link_diagnostic = u8!0x0
should_mitm_all = u8!0x0
should_dump_ssl_traffic = u8!0x0
should_disable_ssl_verification = u8!0x0
```

5. Keep emuMMC, Prelude Nextendo mode, and the existing hosts/trust configuration. Do not add a CA, disable TLS verification, change DNS, or add another Program ID.
6. Reboot fully. Confirm that HOME loads, then perform only one Nintendo Account linking action. Do not install the old ordinary-`ssl` diagnostic package.

## Expected result

The startup log should show `account-link-fallback-v2 ports=ssl:s`. `network_mitm_observer.log` should contain only `SSL SYSTEM` accept records; there should be no ordinary `SSL titleid` record.

Inspect only metadata-only `internal_pki.log` records. Do not record or upload certificates, private keys, tokens, passwords, TLS payloads, or account contents. The successful path is: call the original `RegisterInternalPki` first; only for type 1 with original result `0x0000167B`, call Generate/Import and return the real SSL-service PkiId.

## Verified results and limitation

The target environment has confirmed successful NIM, Account, and NPNS fallback paths, Nintendo Account Link, and Mario Kart 8 Deluxe online play. Deleting an already linked user still fails with `2002-0001`; this release does not support or claim support for that operation.

Do not test Nintendo production endpoints. After testing, follow [README-ROLLBACK.md](README-ROLLBACK.md) and remove the entire module directory.
