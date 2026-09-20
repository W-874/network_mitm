# resource-v3 更新

本文件保留最初接口研究。当前修复和精确AM反汇编依据以 CRASH-ANALYSIS.md 为准：仅注册ssl:s，单管理器16会话/16domain/256对象、2工作线程；targeted=false不再回到legacy广泛接管。原PKI shims和ABI不变。

# SSL Client-PKI investigation — NIM-only v2

Updated 2026-09-20. Target: HOS22.5.0 / Atmosphère1.11.2 / emuMMC. V1 instrumentation produced useful NIM metadata but booted into AM fatal. V2 real console logs confirmed PKI generation/import success, but AM startup fatal persisted. V3 is the current resource repair.

## Feasibility and evidence

The SSL context boundary exposes real key/certificate generation and import, so the proposed replacement is implementable without identity restoration or fake IDs. Two supplied boot traces show program0100000000000025 successfully creating ISslContextForSystem, then command8 type1 returning0x167B. This supports a narrow NIM experiment. It does not prove the cause of AM's UserBreak/0x10801 or locate the manual account-linking2123-0011 failure. See EVIDENCE-v2.md.

The revised requirement intentionally supersedes the original direct-replacement design: call original command8 once, then generate/import only on the observed0x167B. The original call returned an error cleanly in both captures; nevertheless its failed registration could leave context state that prevents import. Preserve and report any such error. No retry of the original identity follows a synthetic generation/import failure.

## Pinned sources

| Source | Commit |
|---|---|
| network_mitm upstream | c15d659600760ac83151e38660c468244176c5b0 |
| Atmosphere-libs submodule | d3083af1827cd6ca2a96feb9316eb85cd01bae1f |
| Atmosphère reference | 6e6af694244002fd6799703a54a5e24f0a0b9ac1 |
| nx-dauth | 6ba8273dfed545424e96a278d7e3506fb7e8d5e6 |
| Prelude-Nro | 6dbd0ea6ab462dd19e7a02fb49b2e6c9c18c05e9 |

[Upstream](https://github.com/nookingtons/network_mitm/commit/c15d659600760ac83151e38660c468244176c5b0), [Atmosphère](https://github.com/Atmosphere-NX/Atmosphere/tree/6e6af694244002fd6799703a54a5e24f0a0b9ac1), [Prelude](https://github.com/NextendoNetwork/Prelude-Nro/tree/6dbd0ea6ab462dd19e7a02fb49b2e6c9c18c05e9), [SSL IPC reference](https://switchbrew.org/w/index.php?title=SSL_services&oldid=15056).

Rechecked nx-dauth main on 2026-09-20; unchanged at the pin. [main.go](https://github.com/NextendoNetwork/nx-dauth/blob/6ba8273dfed545424e96a278d7e3506fb7e8d5e6/main.go) configures tls.NoClientCert at line418. Opening comments describe ignored device crypto; lines288–302 issue mkDeviceToken without console mac/challenge validation. This is source evidence, not a check of the deployed server or all Nextendo endpoints.

## Existing wrappers and original objects

All paths below are relative to this repository. Implementations live under `network_mitm/source/`.

| Interface / wrapper | Files (.hpp/.cpp) |
|---|---|
| ISslService / SslServiceImpl | networkmitm_ssl_service_impl |
| ISslServiceForSystem / SslServiceForSystemImpl | networkmitm_ssl_for_system_service_impl |
| ISslContext / SslContextImpl | networkmitm_ssl_context_impl |
| ISslContextForSystem / SslContextForSystemImpl | networkmitm_ssl_context_for_system_impl |
| ISslConnection / SslConnectionImpl | networkmitm_ssl_connection_impl |

`networkmitm_main.cpp` registers both SSL ports. `ServerManager::OnNeedsToAccept` calls `AcknowledgeMitmSession` to obtain the original Service plus actual process_id/program_id. The wrapper retains that Service; C shims in `shim/ssl_shim.c` use serviceMitmDispatch on it. No separate SSL service/context is opened for PKI import.

Upstream service command0 creates ordinary contexts; ssl:s command100 creates system contexts. Both retain the original service domain object ID when wrapping child objects. V2 leaves ordinary contexts native and wraps only the selected system-context path when that client's tracing or fallback is active.

Both upstream context variants already explicitly implement commands7 RemoveClientPki,8 RegisterInternalPki,12 ImportClientCertKeyPki,13 GeneratePrivateKeyAndCert. Commands12/13 are gated at HOS16.0.0. No new shim or command layout is needed.

## ABI and ownership

The pinned Atmosphere-libs includes Version_22_5_0. Published SSL interface version is5, also observed in v1 console logs. Root interfaces use AMS_SF_DEFINE_MITM_INTERFACE: unhandled root command5 is forwarded. V2 removes the explicit v1 command5 wrapper and never overrides a version.

Context commands7/8/12/13 have no documented new22.5.0 layout. Existing shims match the published enum/buffer/result layouts. KeyAndCertParams size0x58 and member offsets are compile-time checked. DER format is2. Generate uses version1, RSA2048,65537, CN="Nextendo Temporary Client", two4096-byte buffers, and actual returned lengths for import. Storage is wiped via volatile writes on every allocated exit path. No cert/key bytes are logged.

Context interfaces are ordinary AMS_SF_DEFINE_INTERFACE children, not root MITM interfaces with independently attached forward sessions. Returning an unwrapped connection from this registered child would require changing IPC/session ownership. V2 therefore preserves upstream connection ownership and domain IDs, but removes capture, handshake logging and verification changes. The connection constructor performs no extra IPC. RemoveClientPki remains original forwarding.

## Selection and v2 modifications

Both root ShouldMitm callbacks use one program-list policy before session acceptance. The ssl:s server registration previously specified SslServiceImpl; v2 registers SslServiceForSystemImpl so its matching callback is used. Targeted=true overrides should_mitm_all on both ports, including normal applications. Missing new configuration means targeted=true, empty lists and fallback=false. Explicit targeted=false retains upstream service-selection rules but disables the experiment's per-client options; it is not a recommended test configuration.

Per-client options are computed at session acceptance and passed to the system context. Only membership in both MITM and fallback lists permits fallback. Trace does not broaden acceptance. Parser accepts at most16 exact16-hex IDs, rejects the whole malformed/truncated/duplicate list, and accepts an empty list as no targets. Fallback forces metadata logging only for that selected client.

Actual modified files include main, the five wrapper pairs above, networkmitm_utils.hpp; new networkmitm_pki_policy.hpp, networkmitm_device_pki.{hpp,cpp}, networkmitm_synthetic_pki.hpp, networkmitm_pki_trace.{hpp,cpp}; tests/test_pki.cpp, tools/test-host.sh, tools/package.py, config/nim-only.ini.example and these documents. Main no longer loads custom CA or enables PCAP/verification overrides. The observer log is truncated per boot to prevent old broad-interception records remaining at the end of a shorter v2 log. Internal PKI logs append with boot/build markers and8MiB cap.

The existing shims, interface layouts for required PKI commands, submodule, program identity and package location are unchanged. Full and v1-to-v2 diffs are delivered.

## Boundaries and installation

No direct PRODINFO/PRODINFOF/CAL0/BOOT0/BOOT1/BIS/eMMC/serial/eTicket/ssl_rsa_key/fuse access or modification is added. No donor identity, fake ID, firmware ExeFS patch or IPS exists. Original command8 may invoke its normal read of device identity; v2 forwards that once by the revised requirement.

Prelude's source/nextendo_apply.c cleanup removes this module's exefs.nsp,mitm.lst,boot2.flag while provisioning. Keep existing Nextendo redirects and server trust, apply Prelude before installing this package, and do not enable network_mitm CA or verification bypass. No test sends requests to Nintendo.

The upstream Makefile TITLE_ID and network_mitm/network_mitm.json both specify4200000000000666. Package files come from out/sd/atmosphere/contents/4200000000000666. No system_settings.ini or hosts is included. Full backup/rollback steps are in README-TEST.md and README-ROLLBACK.md.

## Validation boundary

Untouched upstream built successfully before initial edits; baseline exefs.nsp SHA256:4cc2ce3730632eb66344db81f34e64d50711fb211bca369debf3ba25691afd94. V2 host routing, exact-error gating, original-success preservation, injected failures and erasure tests pass, including sanitizers; cross-build passes. See BUILD-REPORT.md and the package manifest.

Next runtime gates are: boot successfully with only NIM accepted; observe Generate/Import results; correlate the account action with DNS/API progress; then account linking. A smaller interception scope cannot by itself guarantee that AM's resource-related fatal is gone. New target IDs require specific evidence, never a return to all-system tracing. Ordinary-context evidence would require a separate reviewed implementation, not just an ID-list edit.
