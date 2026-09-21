# Nextendo / network_mitm handoff

## Snapshot

- Inner repository source commit: recorded in the generated package manifest after the final clean-HEAD rebuild.
- Baseline hardware target: HOS 22.5.0 / Atmosphère 1.11.2 / emuMMC /
  Prelude / Nextendo on the user's own device.
- The current source variant is `account-link-fallback-v2`, built on the
  successful resource-v3 NIM fallback. It includes the statically proven
  Account path and the hardware-observed NPNS `ssl:s` path. Host validation and
  static review pass; the generated package manifest is authoritative for the
  clean target build/package, while NPNS hardware confirmation remains pending.

## What hardware has established

1. NIM (`0100000000000025`) uses `ssl:s` / `ISslContextForSystem` and original
   `RegisterInternalPki(DeviceClientCertDefault)` returns `0x0000167B`.
2. The NIM-only fallback is hardware-proven: original call first, then real
   GeneratePrivateKeyAndCert and ImportClientCertKeyPki succeeded and returned
   a real PkiId.
3. resource-v3 booted normally after the earlier broad-interception AM fatal.
4. Manual user-related actions then produced four NPNS (`010000000000002F`)
   crash/fatal pairs with direct `0x167B / 2123-0011`. `ns` and `friends`
   separately reported `0x25A0B`; these are not yet proven PKI failures.

## Current account-link-fallback-v2 implementation

- Registers only `ssl:s` with the existing single ServerManager:
  16 sessions, 16 domains, 256 objects, two workers, `0x10000` pointer buffer.
- NIM, Account, and NPNS remain solely on `ssl:s`. Their fallback remains
  original-first and is gated to type 1 plus original `0x0000167B`; other results
  remain original.
- Ordinary `ssl` is not registered in the current safety release. The previous
  optional ordinary diagnostic accepted systemWeb `0100000000001042` and was
  followed by a network_mitm `4200000000000666` abort; no ordinary client is
  accepted now, even if a stale `enable_account_link_diagnostic` setting remains.
  `should_mitm_all` cannot expand the sole `ssl:s` route.
- No hostname, buffer, payload, token, certificate, private key, account
  content, CA/trust, verification, DNS, handshake, or identity behavior is
  captured or changed.

## Release status

- `tools/test-host.sh`, manifest validation, and `git diff --check` pass for the
  NPNS source changes.
- The NPNS extension must always be target-built and packaged from the exact
  clean HEAD; old Account-only output must not be reused.
- `BUILD-MANIFEST.json` is source metadata only. `tools/package.py` rejects a
  dirty tree and requires a clean-HEAD target build checked by
  `tools/check-binary.py` before it generates package file hashes.

## Sole next hardware decision

After the fresh NPNS target rebuild/check, perform one controlled user-related
action with the existing Prelude configuration and inspect metadata-only logs.
Determine whether NPNS reaches `ssl:s` command 8 type 1, whether exact
`0x0000167B` fallback Generate/Import succeeds, and whether the NPNS fatal plus
related `ns`/`friends` errors disappear.

Do not add `ns` or `friends`, expand ordinary `ssl`, change DNS/CA/trust, or
touch identity material before that evidence is reviewed.

## Non-negotiable prohibitions

Never restore broad interception, `should_mitm_all`, a generic configurable
ordinary-SSL allowlist, extra managers/resources/workers, fake PkiIds, a
verification bypass, PCAP/TLS capture, PRODINFO/CAL0/NAND/firmware changes,
Nintendo identity material, or changes to Prelude routing/trust. Do not access
other devices, accounts, credentials, or external services.
