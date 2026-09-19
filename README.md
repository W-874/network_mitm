# network_mitm: Nextendo damaged-PRODINFO experiment

Experimental fork of [nookingtons/network_mitm](https://github.com/nookingtons/network_mitm/commit/c15d659600760ac83151e38660c468244176c5b0) for HOS **22.5.0**, Atmosphère **1.11.2**, emuMMC.

> 我们不是要伪造 Nintendo 身份，而只是让 Horizon 在访问一个明确不要求 Nintendo client certificate 的第三方 Nextendo 服务时，不因为本机损坏的 PRODINFO DeviceClientCert 而提前退出。

**First install the instrumentation ZIP and establish Level 1.** Source research and cross-builds are complete; console behavior and successful account linking are not verified. See [README-TEST.md](README-TEST.md) (Chinese), [README-ROLLBACK.md](README-ROLLBACK.md), [INVESTIGATION.md](INVESTIGATION.md), and [BUILD-REPORT.md](BUILD-REPORT.md).

Two separate binary artifacts are provided:

- `network_mitm-nextendo-instrumentation.zip`: pure metadata tracing; no fallback implementation. Source tag: `nextendo-instrumentation-v1`.
- `network_mitm-nextendo-broken-prodinfo-poc.zip`: replacement is **off by default**, with an **empty program allowlist**. Source tag: `nextendo-fallback-v1`.

Both ZIPs merge directly into the SD root, using upstream's contents path. Neither replaces system_settings.ini, hosts, Prelude trust files, firmware ExeFS, nor any NAND/calibration/identity data. Do not install the untouched baseline reference binary for this experiment.

## Verified server assumption

At [nx-dauth commit 6ba8273, main.go](https://github.com/NextendoNetwork/nx-dauth/blob/6ba8273dfed545424e96a278d7e3506fb7e8d5e6/main.go#L412-L425), TLS is configured with `ClientAuth: tls.NoClientCert`. The server therefore does not request a TLS client certificate. The [device token handler](https://github.com/NextendoNetwork/nx-dauth/blob/6ba8273dfed545424e96a278d7e3506fb7e8d5e6/main.go#L284-L302) parses client IDs and emits its own tokens without revalidating the console mac/challenge; the opening comments describe this design. This confirms the proposed source-level assumption, not the deployed server version or the policies of unrelated Nextendo services. Recheck upstream before adapting this to a later server; stop if the assumption changes.

## Behavior

With `trace_internal_pki = u8!0x1`, the module records metadata to `/network_mitm/internal_pki.log`: monotonic time, actual caller program/PID, context identity, interface version, PKI type, raw Result, successful PkiId, context/connection creation, deletion and handshakes. The pure tracing branch forwards command8 and its Result unchanged. Capture is disabled in this fork; tracing suppresses upstream CA injection and server-verification bypass. Existing Prelude trust remains external to this module.

The experimental branch additionally requires `enable_device_cert_fallback = u8!0x1` **and** an exact program allowlist entry. Only InternalPki=1 is replaced. The same forwarded context receives command13 with a 2048-bit RSA temporary CN, then command12 with DER (enum=2), and the actual returned ID reaches the caller. Errors remain errors; no PRODINFO retry or fake IDs. Temporary buffers are wiped on every exit. RemoveClientPki remains a real forwarded removal. See config examples and tests for policy and failure behavior.

Only copy program IDs from the failing instrumentation flow. `should_mitm_all` discovers system callers; it does not grant fallback permission. Do not infer a program's identity from a title name.

**Prelude integration:** the examined Prelude version removes stale network_mitm files while provisioning. Apply the existing Prelude Nextendo mode first, then install this ZIP. Do not reprovision during the capture. Keep current DNS redirects; this project does not test Nintendo endpoints.

## Build and tests

The untouched upstream build was completed before applying patches. All variants use the original pinned Atmosphere-libs submodule. Docker's official upstream recipe remains:

```sh
git submodule update --init --recursive
docker compose up --build
```

This environment has Podman rather than Docker; the equivalent devkitPro container was used. Exact tool versions, commands and limitations are in BUILD-REPORT.md. Locally configured devkitPro can also run `make`. `tools/test-host.sh` tests the actual portable policy and generation/import orchestration with a mock transport, including fault injection and buffer erasure. It does not emulate Horizon or perform network requests.

`tools/package.py` validates the Makefile and NPDM IDs and assembles a narrow SD-root ZIP from upstream's packaged output. A complete source archive (including Atmosphere-libs), PATCH.diff and Git history bundle accompany the install artifacts. GPLv2; see LICENSE and upstream copyright notices.
