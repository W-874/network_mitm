# NIM-only v2 build and validation

Date:2026-09-20. The v1 console failed to boot, and its two captured NIM errors motivated this revision. **V2 has not been hardware-tested.** Do not interpret compilation or mock IPC tests as a resolved boot fatal or successful account link.

## Provenance

Untouched upstream c15d659600760ac83151e38660c468244176c5b0 was built successfully before initial modifications. Its exefs.nsp SHA256 is4cc2ce3730632eb66344db81f34e64d50711fb211bca369debf3ba25691afd94. V1 binaries and old build logs remain as historical evidence; they are withdrawn from installation guidance.

Base image: docker.io/devkitpro/devkita64:latest, local image ID551247dfe0524421b8cb608117a767c77823e76608fa2058f0eb5d5398293641.
Prepared image: localhost/nextendo-toolchain:20260920, IDa56fad1e99abdbab62b0e13dde080f2bb47887bb753e95cea4bd6a00a4244f95.

- devkitA64 r30-1; devkita64-gcc16.1.0-1
- libnx4.12.0-1; switch-tools1.13.1-1; switch-mbedtls2.28.10-1
- Atmosphere-libs d3083af1827cd6ca2a96feb9316eb85cd01bae1f, unchanged

The package BUILD-MANIFEST.json records the exact binary-source commit, documentation commit and all packaged file hashes. The build log is distributed alongside the ZIP. The code commits isolate routing/fallback refactoring and observer-log truncation. Documentation may have a later revision without changing executable sources.

## Validation

A clean application rebuild with make -j8 succeeds. Host tests compile with -Wall -Wextra -Werror and pass; they also pass in the toolchain container under AddressSanitizer and UndefinedBehaviorSanitizer. The initial v2 build was repeated after the final observer-log fix so the delivered package includes that change.

Tests exercise actual portable production routing/dispatch helpers:

- Both SSL ports, selected/unselected system clients and applications, legacy should_mitm_all both true/false; default-empty targeted mode intercepts none.
- Per-client trace and fallback intersection; trace cannot broaden selection; fallback forces metadata only for selected clients.
- Strict parsing of up to16 IDs, malformed/truncated/duplicate/all-zero/excess lists, no partial acceptance.
- Original-success ID preservation; Cartesian type/enable/result combinations permit synthetic generation only for type1 + enabled + original0x167B. Other errors and IDs remain unchanged.
- Exactly one original call; original→generate→import ordering; allocation, generation, import, zero/oversized DER length failure propagation; output untouched on error.
- Real imported ID returned and all8192 bytes erased before freeing on every allocated exit path.
- Compile-time KeyAndCertParams size/offset and DER enum checks.

These tests do not exercise the actual service manager, transport ABI, Horizon resource limits, context state after failed registration, the cryptographic implementation, or real network traffic.

Packaging checks: Makefile/JSON program ID agreement, PFS0 contents, NSO signature and NPDM ACI0/ACID program ID/range, ZIP CRC and manifest hashes, no system_settings.ini or hosts replacement, source archive/bundle and patch consistency. Program ID is4200000000000666.

Existing SDK nodiscard/LTO warnings and npdmtool legacy-field warnings remain; build logs retain them. NPDM IDs are inspected rather than assuming those warnings are harmless. No new IPC definitions or shim edits were made.

## Reproduce

Use upstream docker-compose.yml or the above toolchain image, with this checkout and its pinned submodule:

```sh
make -C network_mitm clean
make -j8
SANITIZER_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" tools/test-host.sh
python3 tools/package.py --sd out/sd --output /absolute/path/network_mitm-nextendo-nim-only-v2.zip --variant nim-only-v2 --source-commit nextendo-nim-only-v2
```

The build uses a clean committed source checkout. Package documentation may come from the later documentation commit recorded in the manifest. A source archive includes tracked Atmosphere-libs files; the main-project Git bundle does not contain the submodule repository's Git objects. The complete patch includes current documentation; the package's patch is tied to the binary-source commit.

No validation here contacts Nintendo or modifies SD/NAND/Prelude. Next hardware steps are narrowly scoped in README-TEST.md; keep the rollback instructions ready.
