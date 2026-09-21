# network_mitm: Account Link fallback v2

A resource-bounded SSL Client-PKI experiment for HOS22.5.0 / Atmosphere1.11.2 / emuMMC, based on upstream c15d659600760ac83151e38660c468244176c5b0 and unchanged Atmosphere-libs d3083af1827cd6ca2a96feb9316eb85cd01bae1f.

> 我们不是要伪造 Nintendo 身份，而只是让 Horizon 在访问一个明确不要求 Nintendo client certificate 的第三方 Nextendo 服务时，不因为本机损坏的 PRODINFO DeviceClientCert 而提前退出。

V2's real console logs establish that NIM temporary PKI generation/import succeeds, but AM still fails during GRC process launch. Matching-firmware analysis and the resource repair are in [CRASH-ANALYSIS.md](CRASH-ANALYSIS.md). V1/v2 installation recommendations remain withdrawn.

This test build retains v3's hardware-verified NIM `ssl:s` PKI fallback unchanged, adds the statically proven Account `010000000000001E` `ssl:s` system-context type-1 path, and adds hardware-observed NPNS `010000000000002F` on the same strictly gated `ssl:s` fallback. All three system clients remain exact allowlist entries and use original-first exact-`0x167B` fallback. It also reserves ordinary `ssl`, but accepts it only when `enable_account_link_diagnostic=1` and only from four fixed candidates: qlaunch (`0100000000001000`), LibAppletAuth (`0100000000001011`), systemWeb (`0100000000001042`), and openWeb (`0100000000001043`). The one manager remains at 16 sessions,16 domains,256 objects and two workers; the 64KiB per-session IPC pointer buffer remains. `should_mitm_all` cannot widen either path.

The ordinary path is metadata-only: it forwards `CreateContext` and `RegisterInternalPki` command8 exactly once, recording the fixed build marker, program ID, service, context ID, type and original Result. Its command8 path cannot initiate fallback generation/import or transform a Result; a client that explicitly issues commands12/13 remains transparently forwarded. It never records hostnames, buffers, account data, certificates or keys, and does not modify handshake/trust/verification behavior. On NIM, Account, and NPNS selected system contexts, the original command8→type1/0x167B-only command13→12 fallback is unchanged; Account remains unverified on hardware, while NPNS is observed failing with 0x167B but fallback success is still pending.

Read [README-TEST.md](README-TEST.md) before the single diagnostic installation, and keep [README-ROLLBACK.md](README-ROLLBACK.md). **Replace both exefs.nsp and mitm.lst**: this build requires exactly `ssl` then `ssl:s`. Preserve Prelude Nextendo hosts and trust.

[Current nx-dauth main](https://github.com/NextendoNetwork/nx-dauth/blob/6ba8273dfed545424e96a278d7e3506fb7e8d5e6/main.go) was verified at6ba8273: tls.NoClientCert and its own token issuance without console mac/challenge revalidation. This source assumption does not prove the deployed service version. Stop if the assumption changes.

Upstream was built untouched before the initial patch. Build using the upstream Docker recipe or the equivalent devkitPro container in BUILD-REPORT.md. tools/test-host.sh tests production policy/orchestration; tools/check-binary.py verifies the actual NSP memory budget and service declaration. GPLv2; see LICENSE.

The package includes only the module and documentation. Firmware, prod.keys, decrypted Nintendo executables and private log dumps are not included. The Account/NPNS fallback v2 source is host-tested; the NPNS extension requires a fresh clean target build/package, and the boot plus hardware outcome remain separate gates.
