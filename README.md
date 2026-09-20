# network_mitm: Nextendo resource-v3

A resource-bounded SSL Client-PKI experiment for HOS22.5.0 / Atmosphere1.11.2 / emuMMC, based on upstream c15d659600760ac83151e38660c468244176c5b0 and unchanged Atmosphere-libs d3083af1827cd6ca2a96feb9316eb85cd01bae1f.

> 我们不是要伪造 Nintendo 身份，而只是让 Horizon 在访问一个明确不要求 Nintendo client certificate 的第三方 Nextendo 服务时，不因为本机损坏的 PRODINFO DeviceClientCert 而提前退出。

V2's real console logs establish that NIM temporary PKI generation/import succeeds, but AM still fails during GRC process launch. Matching-firmware analysis and the resource repair are in [CRASH-ANALYSIS.md](CRASH-ANALYSIS.md). V1/v2 installation recommendations remain withdrawn.

V3 retains the successful PKI path and reduces always-resident resources: only ssl:s, one manager,16 sessions,16 domains,256 objects and two service workers. The original64KiB per-session IPC pointer buffer remains. Normal ssl is neither reserved nor registered. A runtime allowlist still gates system clients; the supplied config names only observed NIM0100000000000025. Disabling targeted mode does not enable legacy broad interception.

Defaults: targeted=true, fallback=false, empty lists. On the selected system context, call original command8 once; only type1 and original0x167B permit command13→12 generation/import. Return the real imported ID; propagate errors; erase temporary cert/key storage. Connections forward transparently. No payload capture, custom CA or verification override.

Read [README-TEST.md](README-TEST.md) before installing, and keep [README-ROLLBACK.md](README-ROLLBACK.md). **Replace both exefs.nsp and mitm.lst**: an old two-port startup declaration does not match this binary. Existing correct v2 settings can be retained. Preserve Prelude Nextendo hosts and trust.

[Current nx-dauth main](https://github.com/NextendoNetwork/nx-dauth/blob/6ba8273dfed545424e96a278d7e3506fb7e8d5e6/main.go) was verified at6ba8273: tls.NoClientCert and its own token issuance without console mac/challenge revalidation. This source assumption does not prove the deployed service version. Stop if the assumption changes.

Upstream was built untouched before the initial patch. Build using the upstream Docker recipe or the equivalent devkitPro container in BUILD-REPORT.md. tools/test-host.sh tests production policy/orchestration; tools/check-binary.py verifies the actual NSP memory budget and service declaration. GPLv2; see LICENSE.

The package includes only the module and documentation. Firmware, prod.keys, decrypted Nintendo executables and private log dumps are not included. V3 is built and checked locally; its console boot/account-linking outcome is not yet verified.
