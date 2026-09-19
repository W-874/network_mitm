# Nextendo / damaged PRODINFO SSL investigation

Research date: 2026-09-20. Target: HOS 22.5.0 / Atmosphère 1.11.2 / emuMMC.
Status: source investigation and both binary builds complete; untouched upstream build succeeded (devkitA64 r30 / GCC 16.1.0 / libnx 4.12.0); no on-device evidence yet.

## Scope and feasibility

The proposed replacement is plausible at the SSL context boundary. It does not restore a Nintendo identity. A successful local PKI import is not proof that account linking works. The absence of a DNS log alone does not locate the failure: DNS caching, an unobserved caller, another local identity check, or failure before SSL are alternatives. Hardware Level 1 evidence is mandatory before enabling replacement.

The patch adds no direct access to PRODINFO, PRODINFOF, CAL0, BOOT0/1, BIS, eMMC, serial, eTicket keys, ssl_rsa_key, fuses or donor identity. It does not modify any of them, Nintendo certificate/private keys, Nintendo endpoints, DNS configuration or firmware ExeFS. In instrumentation or nonselected calls, the original SSL service may still attempt its normal device-PKI read; that original behavior is intentionally preserved. Building a homebrew exefs.nsp package is not patching the firmware SSL ExeFS.

## Pinned sources

- network_mitm: `c15d659600760ac83151e38660c468244176c5b0` ("Update for 22.5.0 support"). https://github.com/nookingtons/network_mitm/commit/c15d659600760ac83151e38660c468244176c5b0
- Atmosphere-libs submodule: `d3083af1827cd6ca2a96feb9316eb85cd01bae1f`. No submodule update planned.
- Atmosphère reference: `6e6af694244002fd6799703a54a5e24f0a0b9ac1`; release version macros are 1.11.2. https://github.com/Atmosphere-NX/Atmosphere/tree/6e6af694244002fd6799703a54a5e24f0a0b9ac1
- nx-dauth: `6ba8273dfed545424e96a278d7e3506fb7e8d5e6`. https://github.com/NextendoNetwork/nx-dauth/blob/6ba8273dfed545424e96a278d7e3506fb7e8d5e6/main.go
- Prelude-Nro: `6dbd0ea6ab462dd19e7a02fb49b2e6c9c18c05e9`. https://github.com/NextendoNetwork/Prelude-Nro/tree/6dbd0ea6ab462dd19e7a02fb49b2e6c9c18c05e9
- SSL IPC reference: https://switchbrew.org/w/index.php?title=SSL_services&oldid=15056

## Server assumption: verified in source, not deployment

nx-dauth/main.go:418 configures `ClientAuth: tls.NoClientCert`. Lines 12–16 describe ignoring the console's device crypto. Lines 288–302 parse client IDs and issue their own `mkDeviceToken` without checking mac/challenge. This source-level assumption still holds. Go NoClientCert means the server does not request a TLS client certificate; the client's local attempt to load one can nevertheless fail before a handshake. This does not establish what version the user's remote service is running or the policy of every other Nextendo endpoint.

## Existing wrappers and forward objects

Paths below are relative to network_mitm repository root.

| Interface | Declaration / implementation |
|---|---|
| ISslService / SslServiceImpl | network_mitm/source/networkmitm_ssl_service_impl.{hpp,cpp} |
| ISslServiceForSystem / SslServiceForSystemImpl | network_mitm/source/networkmitm_ssl_for_system_service_impl.{hpp,cpp} |
| ISslContext / SslContextImpl | network_mitm/source/networkmitm_ssl_context_impl.{hpp,cpp} |
| ISslContextForSystem / SslContextForSystemImpl | network_mitm/source/networkmitm_ssl_context_for_system_impl.{hpp,cpp} |
| ISslConnection / SslConnectionImpl | network_mitm/source/networkmitm_ssl_connection_impl.{hpp,cpp} |

`networkmitm_main.cpp` registers MITM for both `ssl` and `ssl:s`. `ServerManager::OnNeedsToAccept` uses `AcknowledgeMitmSession` to get the original `Service` and `sm::MitmProcessInfo`, including **process_id and program_id**. These are carried into contexts and connections; no guessed title-to-process lookup is needed.

Service command 0 `CreateContext` (both services) and `ssl:s` command 100 `CreateContextForSystem` call the existing shim with PID override. On success they wrap the returned `Service` with `CreateSharedObjectEmplaced` and preserve its domain object ID. Context command 2 and system-context command 100 create connections similarly. Destructors close the original service object.

Context commands **7, 8, 12, 13 all already have explicit wrappers and C shims**, for both context variants. 12/13 are guarded for HOS >=16.0.0. Forward IPC uses `serviceMitmDispatch*` in `network_mitm/source/shim/ssl_shim.c`, operating on the original object's `Service`, not a separately opened SSL context.

Important: upstream skips wrapping contexts when both traffic dumping and certificate-verification disabling are off. Tracing must become a third reason to wrap; otherwise enabling only trace would silently miss command 8.

## ABI / HOS 22.5.0

The pinned submodule includes `hos::Version_22_5_0`. No unsupported-version bypass or firmware-version spoofing is needed.

Published SSL interface version is **5** on 22.x. Service command 5 `SetInterfaceVersion` already has a shim but no explicit service wrapper. The root interfaces use `AMS_SF_DEFINE_MITM_INTERFACE`, so unhandled root commands are forwarded; the patch will additionally trace and transparently forward command 5. It will never force version 3/4/5 or confuse this with the separate ApiVersion bits in SslVersion. Root commands 10/11 (21+) also remain transparently forwarded.

Published context 7/8/12/13 layouts have no documented 22.5.0-specific change. Command 8: u32 enum -> u64 ID; command 12: u32 format + two map-alias input buffers -> u64 ID; command 13: u32=1 + params input buffer + cert/key output buffers -> two u32 lengths. Existing shims match these descriptions. No new definition for these commands is necessary. Hardware compatibility is not yet proven by these descriptions or by compilation.

If replacement is implemented, `KeyAndCertParams` must have size 0x58 and offsets 0,4,8,0x10,0x50 (including four final padding bytes); validate with static_assert. Generate with version=1, 2048 bits, exponent=65537, CN="Nextendo Temporary Client"; use the actual returned DER lengths for import. Use CertificateFormat::Der (2), propagate errors, clear private key memory, return the underlying real PKI ID. Do not forward command 8 first; leave RemoveClientPki as a real forward. No fake IDs.

## Integration findings

- Upstream defaults to decrypted PCAP capture. Diagnostic operation must suppress this; no payload/token/password/certificate/key logging.
- Prelude-Nro `source/nextendo_apply.c`, `NEXTENDO_STALE_FILES` and `nextendo_purge_stale`, removes this module's exefs.nsp, mitm.lst and boot2.flag when provisioning Nextendo. Apply existing Prelude mode **before** installing the experimental module and do not reprovision during capture. Do not change the user's hosts.
- Prelude's current trust stack includes version-specific patches and browser CA data; DNS redirection alone does not prove server trust. Preserve the already configured stack. This project must not enable its own disable-verification flag or custom CA injection.
- Program allowlist entries must come from successful capture of the failing flow. Empty list must permit no replacements; system title names are not sufficient evidence.
- Settings/account errors may still come from local device signing outside SSL. Import success with no new DNS means investigate the next boundary, not immediately patch NSO instructions.

## Packaging and intended files

The upstream top-level `Makefile` defines TITLE_ID=`4200000000000666` and packages `out/sd/atmosphere/contents/$(TITLE_ID)/{exefs.nsp,mitm.lst,flags/boot2.flag}`. `network_mitm/network_mitm.json` independently agrees on the title ID. Use this packaging result instead of inventing a contents path. A ZIP must not overwrite system_settings.ini or Prelude hosts.

Planned instrumentation edits: service/context/connection .hpp/.cpp files above; `networkmitm_main.cpp`; `networkmitm_utils.hpp`; new metadata-only tracing helper; documentation and packaging helper. The shim already implements required PKI IPC; do not modify it without a demonstrated ABI reason. The user approved preparing a separate disabled fallback before on-device evidence; fallback adds a shared helper and strict program-ID configuration/parser, with separate trace-only artifact and no prepopulated IDs.

## Validation gates

1. Build untouched upstream first and preserve build log, source hashes, toolchain versions, and binary checksum.
2. Build instrumentation with only forwarded results; package it independently.
3. On emuMMC, prove command 8 with type=1 fails at the user's 2123-0011 action, and record program ID, PID, context ID, timestamps and raw Result. Lack of this evidence is not a fallback success or a confirmed diagnosis.
4. Only then enable a prepared fallback (or implement it after capture), for the observed program IDs; verify generation/import/real ID, DNS, then Nextendo response, then account link.

Untouched baseline NSP SHA-256: `4cc2ce3730632eb66344db81f34e64d50711fb211bca369debf3ba25691afd94`. Build exit status 0. Build logs preserve upstream warnings. npdmtool legacy field notices were checked against the generated ACI0 and ACID: program ID/range are correct.

## Implemented adjustment and current result

The requested hardware gate is preserved as a deployment gate: both builds are prepared, but first install the independently tagged trace-only artifact. The user explicitly chose this two-artifact workflow during this session. No program ID has been guessed or prepopulated. The final fallback default is off and an absent/invalid list permits no replacements.

Implemented metadata helpers: `networkmitm_pki_trace.{hpp,cpp}`. Fallback implementation: `networkmitm_device_pki.{hpp,cpp}`, portable `networkmitm_pki_policy.hpp` and `networkmitm_synthetic_pki.hpp`. The production helper uses existing command13/12 shims on the original Service pointer, 4096 bytes per DER buffer, actual returned lengths, error propagation, volatile memory erasure. Existing `shim/ssl_shim.{h,c}` and Atmosphere-libs remain unchanged.

Host tests and sanitizer runs passed; all three cross-builds passed. See BUILD-REPORT.md for binary source commits, checksums, exact tools and the unverified hardware boundaries. README-TEST.md gives the required Level 1 gate and subsequent Levels 2–5. There is no Plan B fake ID branch and no firmware IPS.
