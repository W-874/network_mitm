# Installation guide

**English** · [中文](README-TEST.md)

Candidate targeting **HOS 23.0.1 / Atmosphère 1.12.1 / emuMMC**. The old library firmware rejection is fixed; device boot/account completion remain unverified for this binary. See [compatibility evidence](HOS23-COMPATIBILITY.md).

Prelude v4.0.19 still refuses Account Link fallback on firmware 23 and bundles the old module. Its button does not install this candidate. Before updating an existing installation, copy the entire `atmosphere/contents/4200000000000666` directory to your computer as a backup.

> New installations do not require you to create or back up a `4200000000000666` folder, and you do not need to place `exefs.nsp`, `mitm.lst`, or `boot2.flag` individually. Extract the complete release package as described below.

## Installation

1. Use the candidate delivered by this build (the old release ZIP does not support firmware 23):

   `network_mitm-hos2301-ams1121-candidate.zip`

2. **Fully power off** the Switch, remove the SD card, and connect it to your computer.

3. Open the ZIP and drag its `atmosphere` and `network_mitm` folders directly onto the **root of the SD card**. If prompted, merge the folders and replace files with the same names.

   The archive creates the required paths automatically. Do not open the folders and copy individual files one by one.

4. Open this file on the SD card:

   `atmosphere/config/system_settings.ini`

   Create the file if it does not exist. Add the configuration below. If the file already contains a `[network_mitm]` section, replace that section instead of adding a duplicate:

   ```ini
   [network_mitm]
   enable_ssl = u8!0x1
   targeted_device_pki_mode = u8!0x1
   mitm_program_ids = str!0100000000000025 010000000000001E 010000000000002F
   trace_internal_pki = u8!0x1
   enable_device_cert_fallback = u8!0x1
   device_cert_fallback_program_ids = str!0100000000000025 010000000000001E 010000000000002F
   enable_account_link_diagnostic = u8!0x0
   should_mitm_all = u8!0x0
   should_dump_ssl_traffic = u8!0x0
   should_disable_ssl_verification = u8!0x0
   ```

5. Safely eject the SD card, return it to the Switch, and boot emuMMC normally.

6. After reaching the HOME Menu, link the Nintendo Account normally. No additional application needs to be run, and `network_mitm` does not need to be started manually.

## Notes

- Keep the existing Prelude hosts, DNS, and trust configuration unchanged.
- Do not add another Program ID, CA, or TLS-verification bypass.
- Do not use this module with Nintendo production endpoints.
- The old HOS 22.5 binary has successful Account Link / Mario Kart 8 Deluxe records; this new HOS 23.0.1 binary has no hardware verification yet.
- Deleting an already linked user still fails with `2002-0001` and is not currently supported.

## Uninstalling

Fully power off the console, then delete this directory from the SD card:

`atmosphere/contents/4200000000000666/`

Remove the complete `[network_mitm]` section from `atmosphere/config/system_settings.ini`, then reboot.
