# Build and validation report

Date: 2026-09-20. Hardware tests: **not performed**; no Switch was attached. No Level 1–5 success is claimed.

## Build provenance

Original upstream and recursive submodule were cloned and kept unchanged until the baseline build and packaging completed successfully. No source compatibility fixes were needed. The initial serial compilation was stopped to resume the same unchanged source with `make -j8`; the final baseline exited 0 before the first source patch. Sub-makes emit a jobserver warning, so not all compilation is parallel.

Base image: `docker.io/devkitpro/devkita64:latest`, local image ID `551247dfe0524421b8cb608117a767c77823e76608fa2058f0eb5d5398293641`.
Prepared toolchain image: `localhost/nextendo-toolchain:20260920`, image ID `a56fad1e99abdbab62b0e13dde080f2bb47887bb753e95cea4bd6a00a4244f95`.

Installed through the upstream recipe (`dkp-pacman -Syu` then `-S --needed switch-dev switch-mbedtls switch-libjpeg-turbo libnx`):

- devkitA64 r30-1; devkita64-gcc 16.1.0-1
- libnx 4.12.0-1; switch-tools 1.13.1-1
- switch-mbedtls 2.28.10-1
- Atmosphere-libs d3083af1827cd6ca2a96feb9316eb85cd01bae1f

| Variant | Binary source commit | exefs.nsp SHA-256 | Build |
|---|---|---|---|
| Untouched upstream | `c15d659600760ac83151e38660c468244176c5b0` | `4cc2ce3730632eb66344db81f34e64d50711fb211bca369debf3ba25691afd94` | PASS |
| Instrumentation | `d8cf75b9d70c1b35748e9e64ced7d456764dd2d1` | `c40c2216ce3fc5365a7e2c1ed27ac1da65881025e18b61ea94d69e03d3511245` | PASS |
| Fallback (default off) | `3e236215c3db7c603d2e32489ee02409b1df879c` | `e4fcd68b612fcf5679195a8622aa04f0237ce1af689742c4e3753a54bbe69614` | PASS |

Source and documentation revisions are separately recorded in each ZIP's BUILD-MANIFEST.json. The two variant binaries were retained before proceeding to the next stage. The baseline is a reference artifact, not the installation recommendation.

## Checks completed

- Untouched upstream: `make -j8`, package generated, exit 0.
- Trace-only source: `make -j8`, package generated, exit 0.
- Fallback source: `make -j8`, package generated, exit 0.
- Host unit/fault-injection tests: `tools/test-host.sh`, PASS with `-Wall -Wextra -Werror`.
- Same tests inside container: `SANITIZER_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" tools/test-host.sh`, PASS; no sanitizer findings. Host system itself lacked libasan, so sanitizer execution used the container.
- Tests cover default-off/empty list, exact program matching, non-device enum pass-through selection, malformed/truncated/duplicate/excess/all-zero IDs, output sizes including boundaries, allocation failure, exact generate/import error propagation, real returned ID, and erasing all temporary storage on success and every failure after allocation.
- Compile-time parameter layout offsets/size and CertificateFormat::Der=2 checks.
- Review of both context paths, no forward-command8 in selected synthetic branch, unchanged RemoveClientPki shims, no certificate/key/payload logging.
- `git diff --check`; packaging script validates module path against NPDM JSON, archive contents and ZIP CRC.

Upstream compiler warnings (mostly existing ignored nodiscard results and LTO serialization) remain. npdmtool warns about legacy field names in the unchanged upstream JSON; generated NPDM ACI0/ACID IDs were independently inspected and match 4200000000000666. These notices are not concealed as a warning-free build.

## Reproduce

Use the original docker-compose.yml, or a container with the above packages:

```sh
make -j8
tools/test-host.sh
```

For the pure tracing code, use tag `nextendo-instrumentation-v1` in a separate checkout (initialize its pinned submodule) and build there. Never switch revisions during an active build. Do not run an unsafe `git reset --hard` over local work.

From the final documentation checkout, package a preserved SD output tree with its actual source commit:

```sh
python3 tools/package.py --sd /absolute/path/to/saved/sd --output /absolute/path/to/output.zip --variant instrumentation --source-commit nextendo-instrumentation-v1
# For the fallback tree use --variant fallback-disabled --source-commit nextendo-fallback-v1
```

Raw logs are delivered in the sibling artifacts directory: upstream-build.log (initial serial run), upstream-build-parallel.log (completed baseline), instrumentation-build.log, fallback-build.log. No tests initiated network traffic to Nintendo or Nextendo; network access was limited to public source/toolchain retrieval.

## Not established by these tests

Runtime module startup, v5 IPC compatibility on the user's exact console, underlying generation/import acceptance, ordinary removal of the imported ID, the origin of 2123-0011, caller allowlist, DNS progress, deployed server trust/policy, and account linking all need the staged on-device test. A successful mock test is not a cryptographic or hardware integration test. The prepared fallback stays gated until that evidence is available.
