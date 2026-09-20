# Supplied console evidence — sanitized metadata

Reviewed2026-09-20. Original logs/config remain outside the source/package; no payloads, account tokens, secrets or full memory dumps are reproduced here. Hashes identify the reviewed originals without distributing them.

| Input | SHA256 |
|---|---|
| 01789858807_0100000000000023_crash_report.log | `f5626e67bad5627fc1baa5aa9f24802fdb22625315dba65e42fcf4faff7d330a` |
| 01789858807_0100000000000023.log | `4aa3fd3a323034ddffcf92277b4be64f183edf42e7073e186582f1630327cb95` |
| network_mitm_observer.log | `da7d04162b39cc823f407c84fff59a7366d0ae38fd23320af00281de43b6f277` |
| internal_pki.log | `b6eaf305196147211edb243a640230bcd8e291e485e814b479c64e422d70c7ac` |
| dns_mitm_startup.log | `d8c7abf93906e346a690220cffd9172ac28b5a31ffc292e82da1b37a3da7c5dd` |
| dns_mitm_debug.log | `30cc8b7992bcd4c7fb9a45233725c34f9c6cf560ff587fbe3ef64d2e3b6d5dc3` |
| system_settings.ini | `82973b5f738b474619eca1c601c16197830db5bed5633994df7697c3b876300b` |

## Observations

- Screenshot/fatal: HOS22.5.0, Atmosphère1.11.2-master-cb4b882e3; program0100000000000023(am); Result0x10801 /2001-0132. The crash report classifies UserBreak. Result0x10801 is LimitReached; “UserBreak” describes the crash mechanism, not the Result name.
- Internal PKI log has two v1 d8cf75b boot blocks. Both select program0100000000000025 (NIM), pid0x72,ctx1, CreateContextForSystem success and RegisterInternalPki type1 failure0x167B.

| Event | First boot monotonic ms | Second boot monotonic ms |
|---|---|---|
| CreateContextForSystem begin | 20333 | 20270 |
| CreateContextForSystem success | 20336 | 20274 |
| RegisterInternalPki begin | 20339 | 20277 |
| RegisterInternalPki result0x167B | 20345 | 20282 |

- SetInterfaceVersion=5 succeeded in both boot blocks.
- Observer accepts unrelated system clients (suffixes33,25,0f,0e,30,2f,1e,2e,0c,3e). Existing configuration explicitly enables should_mitm_all and trace_internal_pki; fallback is off, dumping/disable-verification are off.
- DNS startup selects /hosts/emummc.txt. Supplied short DNS debug log contains no dauth/aauth/accounts/baas entry. This absence is not proof of one unique failure boundary, especially with a boot fatal and potential caching.

## What this supports

There is direct evidence for the NIM system-context command8 failure. The user authorized targeting that one ID and trying fallback only for its observed0x167B. There is no need to reinstall the broad tracer to rediscover that fact.

The logs do not establish that broad interception alone caused AM's fatal, that NIM's boot-stage error is the manual account-linking2123-0011 cause, that a failed registration leaves the context usable for import, or that v2 will boot/link successfully. These remain runtime questions. We did not re-analyze AM backtraces or attempt changes to AM/other clients.
