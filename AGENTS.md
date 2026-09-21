# Nextendo / network_mitm durable constraints

## Purpose and safety boundary

- This is local compatibility research for the user's own HOS 22.5.0 /
  Atmosphère 1.11.2 / emuMMC Switch and its chosen Prelude / Nextendo setup.
- The purpose is to let Horizon progress past demonstrated local client-PKI
  initialization failures. It is not Nintendo-account authentication bypass,
  identity restoration, impersonation, credential collection, or operation
  against Nintendo production services.
- Do not access, modify, restore, copy, print, import, imitate, package, or
  upload PRODINFO/PRODINFOF, CAL0, BOOT0/BOOT1, BIS/eMMC/NAND identity, serial
  data, fuses, eTicket material, `ssl_rsa_key`, Nintendo certificates/private
  keys, or firmware ExeFS/IPS. `Firmware/` and `prod.keys` are read-only local
  inputs and must never enter logs or artifacts.
- Do not alter Prelude hosts, DNS/routing, CA/trust, TLS verification,
  endpoints, or the user's existing configuration. Do not deploy, contact
  external accounts, or test Nintendo endpoints.
- Never log or capture hostnames, TLS/IPC buffers, payloads, passwords,
  tokens, certificates, private keys, or account data. Never write generated
  key/certificate material to SD; wipe temporary in-memory key material.

## Hardware-proven baseline

- Broad `should_mitm_all=1` instrumentation accepted unrelated clients and was
  followed by AM (`0100000000000023`) fatal `2001-0132` / `0x10801`. It must
  never be restored.
- NIM is `0100000000000025`; it successfully called
  `CreateContextForSystem`, then original `RegisterInternalPki`
  `DeviceClientCertDefault` (type 1) returned `0x0000167B`, twice.
- Targeted v2 proved the real NIM fallback: original `0x167B`, successful
  command 13 GeneratePrivateKeyAndCert, successful command 12
  ImportClientCertKeyPki, and a real returned PkiId.
- resource-v3's NIM-only `ssl:s` build booted successfully. A manual Account
  Link still returned `2123-0011` without a new NIM PKI trace or account DNS.

## account-link-fallback-v2 constraints

- v2 preserves NIM's `ssl:s` fallback, adds Account `010000000000001E`, and
  now adds hardware-observed NPNS `010000000000002F`: original-first; only
  these three exact IDs, type 1, and original `0x0000167B` may generate/import
  a real PKI ID.
- It uses one ServerManager only: 16 sessions, 16 domains, 256 objects, two
  workers, and a `0x10000` pointer buffer. Do not add a manager, workers, or
  resource pool.
- Ordinary `ssl` is an opt-in, metadata-only diagnostic when
  `enable_account_link_diagnostic=1`. Its hard-coded candidates are only
  qlaunch `0100000000001000`, LibAppletAuth `0100000000001011`, systemWeb
  `0100000000001042`, and openWeb `0100000000001043`.
- Service separation is strict: NIM, Account, and NPNS are only `ssl:s`; the
  four candidates are only ordinary `ssl`; no configurable ID, missing configuration, or
  `should_mitm_all` may widen either route.
- For the four ordinary candidates, record only build marker, program ID,
  service, context ID, original CreateContext result, and command-8 type/result.
  Ordinary RegisterInternalPki must return the original result and never
  trigger/issue fallback Generate/Import. Client-initiated command 12/13 stays
  transparently forwarded by the existing context wrapper.

## Workflow and stop conditions

- Separate source/host evidence from target-build and hardware evidence.
  account-link-fallback-v2 has now passed a clean target build and binary
  check, but is not installed or hardware-verified; Account hardware success
  remains unknown until the controlled test.
- Do not package, rename, or install resource-v3 output as account-link-fallback-v2.
- The next hardware question is whether Account reaches its proven `ssl:s`
  Context command 8 type-1 path and whether the exact fallback removes local
  `2123-0011`. Preserve relevant logs before any scope change.
- If it does not, or returns another result, do not add IDs, fallback paths,
  interception scope, certificate changes, or identity changes without new
  evidence and a narrowly reviewed plan.

## Account system-context fallback evidence (2026-09-21)

Static Account Program `010000000000001E` evidence now proves a real `ssl:s`
path: root version 5 -> `CreateContextForSystem` command 100 -> Context
command 8 with `InternalPki` type 1 (`DeviceClientCertDefault`) at Account
callers `0x000d7958`, `0x0013e9d4`, and `0x0013ea18`. The implementation
adds this exact Program ID to the strict system-SSL allowlist and reuses the
existing original-first exact-`0x0000167B` fallback. Do not add ordinary `ssl`,
do not intercept generic HIPC manager commands, and do not broaden any other
program or PKI type.

## NPNS hardware evidence (2026-09-21)

Four crash/fatal report pairs identify NPNS `010000000000002F` as a direct
repeated `0x0000167B` / `2123-0011` producer. The current implementation adds
NPNS to the strict `ssl:s` allowlist and reuses the same exact type-1 fallback;
`ns` and `friends` `0x25A0B` reports are not fallback targets. NPNS fallback
success remains unverified until the next controlled console run.
