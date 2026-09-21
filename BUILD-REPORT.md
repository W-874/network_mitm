# account-link-fallback-v2 build report

This source tree contains a **controlled diagnostic**. The NPNS extension has
passed host tests and static review; the generated package manifest is the
authoritative record of the clean target build, binary check, and package
hashes for the exact source HEAD. It is not hardware-verified. The previously
built `resource-v3` package is historical evidence only and must not be
renamed, repacked, or installed as this variant.

## Current clean target build

- The final package must be built from a clean source HEAD; its generated
  package manifest records the exact source commit, NSP hash, NSO build ID, and
  documentation-file hashes.
- Target toolchain: devkitA64 `aarch64-none-elf-g++ 15.2.0`.
- The checker must report Program ID `4200000000000666`, NSO BSS below 3 MiB,
  and the only reserved port is `ssl:s`; variant is
  `account-link-fallback-v2`.
- Account and NPNS system-context fallback were observed in the latest metadata-only trace: original `0x167B`, successful Generate/Import, and real PkiId. Full Account Link business completion remains unverified.

## Scope

- Retains resource-v3's hardware-proven NIM (`0100000000000025`) `ssl:s`
  fallback: original command 8 first; only type 1 plus original `0x0000167B`
  may generate/import a real PKI ID.
- Adds the exact Account `ssl:s` type-1 fallback and the hardware-observed NPNS
  `ssl:s` type-1 fallback. Ordinary `ssl` is not registered in this release.
  The prior ordinary diagnostic accepted only fixed candidates but is disabled
  after the `4200000000000666` abort observed immediately after systemWeb
  `CreateContext`.
- Account `010000000000001E` and NPNS `010000000000002F` now have metadata-only
  traces showing original `0x167B`, successful Generate/Import, and a real PkiId.
  This does not prove the final account-link business result.

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
The checker must report exactly one port: `ssl:s`. The package
manifest, not this source document, is authoritative for the final package
file hashes.

## Historical records

The v3 build facts, its resource measurements, and its SHA-256 values remain
in `artifacts/resource-v3/`. They apply only to v3's `ssl:s`-only NSP. The
earlier NIM PKI observations and AM analysis remain in `EVIDENCE-v2.md` and
`CRASH-ANALYSIS.md`; neither proves this diagnostic build or Account Link
completion.


## 2026-09-21 system-only safety rebuild scope

The next release removes the ordinary `ssl` MITM registration and emits a single-line `mitm.lst` containing only `ssl:s`. This is a deliberate safety boundary after the hardware-observed network_mitm `4200000000000666` abort following ordinary systemWeb `0100000000001042` `CreateContext`. The NIM, Account, and NPNS system `ssl:s` fallback implementation is unchanged.
