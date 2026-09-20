# resource-v3 build report

The exact delivered source commit and file hashes are in BUILD-MANIFEST.json. V3 has no completed console test yet. V2 real-console PKI success and AM fatal are recorded in CRASH-ANALYSIS.md.

## Toolchain and baseline

Untouched upstream c15d659600760ac83151e38660c468244176c5b0 was built before initial edits. Baseline NSP SHA2564cc2ce3730632eb66344db81f34e64d50711fb211bca369debf3ba25691afd94.
Unchanged Atmosphere-libs d3083af1827cd6ca2a96feb9316eb85cd01bae1f.
Container localhost/nextendo-toolchain:20260920, IDa56fad1e99abdbab62b0e13dde080f2bb47887bb753e95cea4bd6a00a4244f95; devkitA64r30-1, gcc16.1.0-1, libnx4.12.0-1, switch-tools1.13.1-1, switch-mbedtls2.28.10-1.

## Checks

- Clean application cross-build and NSP packaging.
- Production routing/fallback tests with -Wall -Wextra -Werror; ASan and UBSan runs.
- Ordinary ssl always rejected by policy; targeted=false and stale should_mitm_all=true cannot enable broad mode. Exact NIM list/type1/original0x167B gate and all earlier generation/import/error/erasure tests retained.
- Compile-time manager size<1152KiB; sizeof(KeyAndCertParams)=0x58 and member offsets, DER enum unchanged.
- Actual NSP PFS0/NSO/NPDM identity and memory budget checks. Startup declaration must be exactly ssl:s. BSS<3MiB and savings against v2>=8MiB. Exact values are in MEMORY-VERIFICATION.json outside the ZIP and file hashes in its manifest.
- ZIP CRC/manifest verification; no system_settings.ini, hosts, firmware or keys in package. Source tar uses Git tracked files only; private-analysis, root Firmware and prod.keys are outside that tree.

The manager is now0x1055C0 bytes instead of two0x4C6DF8-byte objects. Session capacity is intentionally16, with16domains and256objects; this is not a tested substitute for a system-wide proxy. Per-session pointer buffer remains65536 bytes to preserve the upstream acceptance constraint. Service worker count is2; this excludes library/internal threads.

Read-only resource queries use already-permitted GetInfo/GetResourceLimit* SVCs. GetInfo ResourceLimit requires InvalidHandle and returns a new handle, which is closed on every subsequent exit. No service is contacted to raise quotas. Snapshot failures are logged without replacing PKI Results; logging-ready state is atomic across workers.

Existing SDK nodiscard/LTO and legacy npdmtool warnings remain visible in build logs. Generated ACI0/ACID program identity is independently checked.

## Reproduce

```sh
make -C network_mitm clean
make -j8
SANITIZER_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" tools/test-host.sh
python3 tools/check-binary.py --sd out/sd --baseline /path/to/v2/exefs.nsp
python3 tools/package.py --sd out/sd --output /path/to/network_mitm-nextendo-resource-v3.zip --source-commit nextendo-resource-v3
```

Measured static footprint and mock tests do not establish shared kernel headroom on the user's running setup. V3's next validation is normal HOME startup, preserved PKI success and then account-flow progress. No claim of completed account linking is made.
