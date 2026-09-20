# network_mitm: Nextendo NIM-only v2

Experimental fork for HOS **22.5.0**, Atmosphère **1.11.2**, emuMMC, based on [nookingtons/network_mitm c15d659](https://github.com/nookingtons/network_mitm/commit/c15d659600760ac83151e38660c468244176c5b0).

> 我们不是要伪造 Nintendo 身份，而只是让 Horizon 在访问一个明确不要求 Nintendo client certificate 的第三方 Nextendo 服务时，不因为本机损坏的 PRODINFO DeviceClientCert 而提前退出。

**Retire the v1 broad instrumentation and fallback packages.** The supplied v1 console logs show two NIM system-context DeviceClientCertDefault failures (0x167B), alongside an AM boot fatal. The causal link between broad interception and that fatal is not proven. This revision limits interception before session acceptance and retries only the observed failure. It is built and host-tested, but has **not** been boot-tested on a Switch.

Install `network_mitm-nextendo-nim-only-v2.zip` using [README-TEST.md](README-TEST.md); keep [README-ROLLBACK.md](README-ROLLBACK.md) available. [EVIDENCE-v2.md](EVIDENCE-v2.md) records sanitized observations; [INVESTIGATION.md](INVESTIGATION.md) describes source/ABI findings; [BUILD-REPORT.md](BUILD-REPORT.md) records validation.

## Scope and behavior

Both `ssl` and `ssl:s` use the same program allowlist in targeted mode. The supplied configuration selects only observed NIM `0100000000000025`; `should_mitm_all` is ignored. Per-client trace/fallback options are captured when accepting a session. Missing new configuration defaults to targeted=true and empty lists, so installing over v1 settings cannot silently restore broad interception. Fallback defaults to false.

Only `ISslContextForSystem::RegisterInternalPki` can replace a failed operation. It calls original command8 once. Original success returns its real ID; other errors pass through. Only selected client + InternalPki=1 + original Result=0x167B triggers command13 GeneratePrivateKeyAndCert followed by command12 ImportClientCertKeyPki on that same context. Parameters: RSA2048, exponent65537, CN="Nextendo Temporary Client", DER. The returned ID is real, and RemoveClientPki remains unchanged. Generation/import failures are returned; temporary buffers are securely erased on every exit after allocation.

Ordinary contexts are handed to the original service. System-context connections retain upstream object ownership and transparent forwarding: no handshake tracing, PCAP, custom CA, or verification overrides. Root command5 SetInterfaceVersion again uses the upstream unhandled-command forward path. No IPC definitions, submodules, firmware ExeFS, identity data, NAND or DNS are patched.

## Server assumption

Rechecked on 2026-09-20: nx-dauth main is still [6ba8273, main.go](https://github.com/NextendoNetwork/nx-dauth/blob/6ba8273dfed545424e96a278d7e3506fb7e8d5e6/main.go#L412-L425), with `ClientAuth: tls.NoClientCert`. Its [device token handler](https://github.com/NextendoNetwork/nx-dauth/blob/6ba8273dfed545424e96a278d7e3506fb7e8d5e6/main.go#L284-L302) issues its own token without revalidating console mac/challenge; opening comments describe ignored device crypto. This verifies current source, not the deployed version or other Nextendo services. Stop and reassess if the server assumption changes.

Prelude provisioning can remove this module's files. Keep current Prelude Nextendo mode, DNS and trust configuration; apply Prelude first and this package afterward. The ZIP does not replace system_settings.ini or hosts. Merge only the supplied network_mitm keys into the existing settings section.

## Build

Untouched upstream was successfully built before any initial modification. The original pinned Atmosphere-libs submodule remains unchanged. Upstream's Docker recipe remains usable:

```sh
git submodule update --init --recursive
docker compose up --build
```

This workspace uses the equivalent devkitPro container via Podman. See BUILD-REPORT.md for versions and commands. `tools/test-host.sh` tests actual portable routing and fallback orchestration with fault injection; it does not emulate Horizon IPC. A source archive with the submodule, Git bundle, patch and build log accompany the SD package. GPLv2; see LICENSE.
