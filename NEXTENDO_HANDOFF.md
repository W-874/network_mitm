# Nextendo / network_mitm handoff

## Snapshot

- Inner repository source commit: recorded in the generated package manifest after the final clean-HEAD rebuild.
- Baseline hardware target: HOS 22.5.0 / Atmosphère 1.11.2 / emuMMC /
  Prelude / Nextendo on the user's own device.
- The current source variant is `account-link-fallback-v2`, built on the
  successful resource-v3 NIM fallback. It now includes the statically proven
  Account `ssl:s` system-context type-1 path; target NSP and binary/resource checks now pass; the final clean-HEAD
  rebuild and package remain release-gate outputs, and hardware remains pending.

## What hardware has established

1. NIM (`0100000000000025`) uses `ssl:s` / `ISslContextForSystem` and original
   `RegisterInternalPki(DeviceClientCertDefault)` returns `0x0000167B`.
2. The NIM-only fallback is hardware-proven: original call first, then real
   GeneratePrivateKeyAndCert and ImportClientCertKeyPki succeeded and returned
   a real PkiId.
3. resource-v3 booted normally after the earlier broad-interception AM fatal.
4. Manual Nintendo Account Link still showed `2123-0011`; this produced no
   second NIM PKI trace and no account-related DNS request. Therefore NIM's
   successful fallback does not identify the later local failure.

## Current account-link-fallback-v2 implementation

- Registers exactly `ssl` and `ssl:s` with the existing single ServerManager:
  16 sessions, 16 domains, 256 objects, two workers, `0x10000` pointer buffer.
- NIM and Account remain solely on `ssl:s`. Their fallback remains original-first and is
  gated to type 1 plus original `0x0000167B`; other results remain original.
- Ordinary `ssl` is disabled unless `enable_account_link_diagnostic=1` and is
  hard-limited to qlaunch `0100000000001000`, LibAppletAuth
  `0100000000001011`, systemWeb `0100000000001042`, and openWeb
  `0100000000001043`. These IDs cannot use `ssl:s`; NIM cannot use ordinary
  `ssl`; `should_mitm_all` cannot expand selection.
- For an accepted ordinary candidate it records only build marker, program ID,
  service, context ID, original CreateContext result, and command-8 type/raw
  result. Its RegisterInternalPki never invokes fallback or Generate/Import;
  client-issued command 12/13 remains transparent forwarding.
- No hostname, buffer, payload, token, certificate, private key, account
  content, CA/trust, verification, DNS, handshake, or identity behavior is
  captured or changed.

## Release status

- `tools/test-host.sh`, Python syntax validation, and `git diff --check` have
  passed for the source changes.
- The clean target compilation exposed one concrete shim return-type error
  (`.GetValue()` on the global scalar `Result`); it was corrected in
  `323c587`. A new clean target rebuild, binary/resource check, and package
  generation remain pending; old resource-v3 output is not valid for this
  variant.
- `BUILD-MANIFEST.json` is source metadata only. `tools/package.py` rejects a
  dirty tree and requires a clean-HEAD target build checked by
  `tools/check-binary.py` before it generates package file hashes.

## Sole next hardware decision

After a clean target rebuild/check, perform one controlled Account Link action
with the existing Prelude configuration and inspect the metadata-only logs.
Determine whether any one fixed ordinary candidate reaches command 8 and its
raw result is `0x0000167B`.

- If yes, that exact service/program/context evidence can justify a separately
  reviewed minimal compatibility extension.
- If no, or the raw result differs, stop: do not add candidates, expand
  interception, introduce fallback, change DNS/CA/trust, or touch identity
  material. Preserve the new observer/internal-PKI/DNS/fatal logs first.

## Non-negotiable prohibitions

Never restore broad interception, `should_mitm_all`, a generic configurable
ordinary-SSL allowlist, extra managers/resources/workers, fake PkiIds, a
verification bypass, PCAP/TLS capture, PRODINFO/CAL0/NAND/firmware changes,
Nintendo identity material, or changes to Prelude routing/trust. Do not access
other devices, accounts, credentials, or external services.
