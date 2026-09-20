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

## account-link-diagnostic-v1 constraints

- v1 preserves NIM's `ssl:s` fallback exactly: original-first; only NIM,
  type 1, and original `0x0000167B` may generate/import a real PKI ID.
- It uses one ServerManager only: 16 sessions, 16 domains, 256 objects, two
  workers, and a `0x10000` pointer buffer. Do not add a manager, workers, or
  resource pool.
- Ordinary `ssl` is an opt-in, metadata-only diagnostic when
  `enable_account_link_diagnostic=1`. Its hard-coded candidates are only
  qlaunch `0100000000001000`, LibAppletAuth `0100000000001011`, systemWeb
  `0100000000001042`, and openWeb `0100000000001043`.
- Service separation is strict: NIM is only `ssl:s`; the four candidates are
  only ordinary `ssl`; no configurable ID, missing configuration, or
  `should_mitm_all` may widen either route.
- For the four ordinary candidates, record only build marker, program ID,
  service, context ID, original CreateContext result, and command-8 type/result.
  Ordinary RegisterInternalPki must return the original result and never
  trigger/issue fallback Generate/Import. Client-initiated command 12/13 stays
  transparently forwarded by the existing context wrapper.

## Workflow and stop conditions

- Separate source/host evidence from target-build and hardware evidence.
  account-link-diagnostic-v1 is not target-built, binary-checked, installed,
  or hardware-verified until a clean target build succeeds.
- Do not package, rename, or install resource-v3 output as diagnostic-v1.
- The only next hardware question is whether one fixed ordinary candidate,
  during one manual Account Link, calls command 8 and returns raw `0x167B`.
  Preserve relevant logs before any scope change.
- If it does not, or returns another result, do not add IDs, fallback paths,
  interception scope, certificate changes, or identity changes without new
  evidence and a narrowly reviewed plan.
