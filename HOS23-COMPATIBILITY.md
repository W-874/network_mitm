# HOS 23.0.1 / Atmosphère 1.12.1 compatibility candidate

Snapshot: 2026-11-07, Asia/Hong_Kong. Variant: `account-link-fallback-v2-hos2301`.

## Confirmed defect and correction

The previous Atmosphere-libs pin `d3083af1827cd6ca2a96feb9316eb85cd01bae1f`
defines `Version_Max` as HOS 22.5.0. Its actual
`libstratosphere/source/hos/hos_version_api.cpp:InitializeVersionInternal`
rejects an Exosphère target firmware whose major/minor exceeds that maximum.
`__appInit` initializes HOS before the module's `Main`, so this rejection can
abort the module before it accepts any SSL client.

This candidate pins the official Atmosphère 1.12.1 library snapshot
`cf48d23375cf36742876f4b014971b2ebabc6dc8`, which recognizes 23.0.0/23.0.1
and includes the upstream ShadowStack address-space changes. It also includes
upstream `f32c8c5d`'s copy-handle cleanup in MITM ForwardRequest. We use the
complete supported library update, not a binary patch or a disabled assertion.

The build pins libnx `cd824f90c48e4210827df7c09dd0f7302f0dc051`, whose
BatchRead filesystem definitions are required by these new library headers.
The base container's libnx 4.12.0 fails to compile those headers. Exact inputs
are in `BUILD-DEPS.json`, and the packaged `TARGET-BUILD.json` binds the NSP hash
to the clean source commit and dependency pins.

## Validation and limits

`tests/test_firmware.py` compiles the **unchanged upstream initializer and
version headers** from both pins with mocked platform I/O. The old source
rejects 23.0.0/23.0.1 and accepts 22.5.0. The new source accepts all three;
23.1.0 and 24.0.0 remain rejected. This is host evidence for the exact version
gate, not execution on a Switch or correlation with a particular crash PC.

The existing routing/fallback tests, a clean target build and NSP checks are
the offline acceptance gates. The generated delivery report records their
actual outcomes. HOS 23 boot, Account/NPNS calls, account completion, online
play and HOS 22.5 device regression are **not hardware verified for this binary**.
The historical HOS 22.5 results apply only to the previous binary.

The patch preserves the sole `ssl:s` registration, exact NIM/Account/NPNS IDs,
original-first type-1/exact-`0x167B` fallback, TLS/trust behavior and resource
limits. It does not add guessed SSL command layouts. Existing child context
and connection interfaces use explicit wrappers; unknown child commands are
not transparently forwarded. No new HOS 23 child command or changed wire ABI
has been established by this investigation. A macro-only switch to MITM child
interfaces is unsafe because upstream non-domain returned objects are
registered with `RegisterSession`, whereas `ForwardRequest` requires a MITM
session. That limitation is retained and is not claimed fixed.

## Upstream Prelude relationship

Atmosphère latest official release is 1.12.1 (2026-10-16). Nextendo's old
`Prelude-Nro` repository redirects to `NextendoNetwork/Prelude-Nextendo`;
latest release at this snapshot is v4.0.19, source
`ae349b3d1a722ea0c222ec4a9867b6f46ddc17c8` (2026-11-07).

Prelude's source still blocks **Account Link fallback installation on firmware
23 and newer**, and CI still bundles the old W-874 v2 NSP with SHA-256
`ec179ddc06e671197b5b7df210e3676871d1d469a91aec191e31ad1f7d5efc2d`.
Its firmware-23 DNS/browser updates do not establish this module's compatibility.
Do not treat the Prelude Account Link button as installing this new candidate:
the candidate must be explicitly staged from its matching package. This patch
does not remove Prelude's firmware guard or replace its bundled old binary.
Upstream installer integration remains a separate step after device validation.

Primary references:

- https://github.com/Atmosphere-NX/Atmosphere/releases/tag/1.12.1
- https://github.com/Atmosphere-NX/Atmosphere-libs/commit/cf48d23375cf36742876f4b014971b2ebabc6dc8
- https://github.com/Atmosphere-NX/Atmosphere-libs/commit/f32c8c5dc1c049da33cedb294495c16fa3337a35
- https://github.com/switchbrew/libnx/commit/cd824f90c48e4210827df7c09dd0f7302f0dc051
- https://github.com/NextendoNetwork/Prelude-Nextendo/blob/ae349b3d1a722ea0c222ec4a9867b6f46ddc17c8/source/nextendo_apply.c#L1792-L1835
- https://github.com/NextendoNetwork/Prelude-Nextendo/blob/ae349b3d1a722ea0c222ec4a9867b6f46ddc17c8/.github/workflows/build.yml#L120-L141
- https://github.com/NextendoNetwork/Prelude-Nextendo/issues/42

Issue 42 includes a third-party boot-only workaround. Its attachment was not
downloaded or incorporated, and its author does not explicitly establish account
completion. The source fix here follows the verified library version gate.
