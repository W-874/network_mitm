# account-link-fallback-v2 build report

This source tree contains a **controlled diagnostic** and now has a clean target
build plus binary check. It is not hardware-verified. The previously built
`resource-v3` package is historical evidence only and must not be renamed,
repacked, or installed as this variant.

## Current clean target build

- Source commit used for the build: `152a45d` (the release documentation
  update below will be rebuilt before packaging so the binary marker matches
  the final clean HEAD).
- Target toolchain: devkitA64 `aarch64-none-elf-g++ 15.2.0`.
- Target NSP SHA-256: `9a204ac162891c0f09423f359387cf27269eda273faeb23f07d8bb862ed8227f`.
- Program ID: `4200000000000666`.
- NSO BSS: `2231336` bytes; mapped image end (page aligned): `2547712` bytes.
- Binary checker: passed; ports are exactly `ssl`, then `ssl:s`; variant is
  `account-link-fallback-v2`.
- Account hardware result: unknown; no console claim is made by this build.

## Scope

- Retains resource-v3's hardware-proven NIM (`0100000000000025`) `ssl:s`
  fallback: original command 8 first; only type 1 plus original `0x0000167B`
  may generate/import a real PKI ID.
- Adds the exact Account `ssl:s` type-1 fallback and retains an opt-in ordinary `ssl` diagnostic for exactly qlaunch
  (`0100000000001000`), LibAppletAuth (`0100000000001011`), systemWeb
  (`0100000000001042`), and openWeb (`0100000000001043`). It records only the
  build marker, program ID, service, context ID, command-0 result, and
  command-8 type/result.
- Ordinary `RegisterInternalPki` has no fallback: its command 8 path never
  initiates Generate/Import. A client that explicitly issues commands 12/13
  still receives the existing transparent forwarding behavior. The diagnostic
  does not record hostnames, IPC/TLS buffers, account data, tokens,
  certificates, or private keys; it does not change TLS trust, verification,
  DNS, or handshake behavior.
- Account `010000000000001E` uses the same `ssl:s` system Context boundary as NIM; it is statically proven but not hardware-verified.
- Uses the existing single ServerManager: 16 sessions, 16 domains, 256 domain
  objects, two workers, and a 64 KiB pointer buffer. It does not restore
  `should_mitm_all` or add workers/resource pools.

## Build and release gate

`BUILD-MANIFEST.json` is a reviewable source input, intentionally without
binary or package hashes. `tools/package.py` reads and validates it, then adds
the exact package-file hashes only after a clean target build has passed the
binary checker. It refuses a dirty source tree or a source commit other than
the checked-out clean HEAD. This prevents presenting an old v3 `out/` tree as
a new diagnostic build.

Required target-environment sequence:

```sh
network_mitm/tools/test-host.sh
make -C network_mitm clean
make -C network_mitm
python3 network_mitm/tools/check-binary.py --sd network_mitm/out/sd
python3 network_mitm/tools/package.py \
  --sd network_mitm/out/sd \
  --output /path/to/network_mitm-account-link-fallback-v2.zip \
  --source-commit HEAD
```

Only after all commands succeed may the generated ZIP and its generated
`network_mitm/docs/BUILD-MANIFEST.json` be treated as the release artifact.
The checker must report both ports in order: `ssl`, then `ssl:s`. The package
manifest, not this source document, is authoritative for the final package
file hashes.

## Historical records

The v3 build facts, its resource measurements, and its SHA-256 values remain
in `artifacts/resource-v3/`. They apply only to v3's `ssl:s`-only NSP. The
earlier NIM PKI observations and AM analysis remain in `EVIDENCE-v2.md` and
`CRASH-ANALYSIS.md`; neither proves this diagnostic build or Account Link
completion.
