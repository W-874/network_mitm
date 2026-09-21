# 安装指南

[English](README-TEST.en.md) · **中文**

适用于 **HOS 22.5.0 / Atmosphère 1.11.2 / emuMMC**，并且已经配置好 Nextendo Prelude 的主机。

> 新安装用户不需要提前创建或备份 `4200000000000666` 文件夹，也不需要手动放置 `exefs.nsp`、`mitm.lst` 或 `boot2.flag`。直接解压整个发布包即可。

## 安装步骤

1. 从 [Releases](https://github.com/W-874/network_mitm/releases/tag/v2.0.0-account-link-fallback) 下载：

   `network_mitm-account-link-fallback-v2-system-only.zip`

2. 将 Switch **完全关机**，取出 SD 卡并连接电脑。

3. 打开 ZIP，把里面的 `atmosphere` 和 `network_mitm` 文件夹直接拖到 **SD 卡根目录**。出现提示时选择合并文件夹并覆盖同名文件。

   解压后的路径会由压缩包自动创建。不要进入文件夹逐个复制文件。

4. 打开 SD 卡上的：

   `atmosphere/config/system_settings.ini`

   如果文件不存在，就创建它。加入以下配置；如果已经有 `[network_mitm]` 段，请用下面的内容替换该段，不要创建两个同名段：

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

5. 安全弹出 SD 卡，装回 Switch，然后正常启动 emuMMC。

6. 进入 HOME 菜单后，按正常流程关联 Nintendo Account。无需运行额外程序，也无需手动启动 `network_mitm`。

## 注意事项

- 保持现有 Prelude hosts、DNS 和信任配置不变。
- 不要添加其他 Program ID、CA 或 TLS verification bypass。
- 不要将本模块用于 Nintendo production endpoint。
- 已确认 Account Link 和 Mario Kart 8 Deluxe 联机可用。
- 删除已经关联的用户仍会报 `2002-0001`，目前不支持该操作。

## 卸载

完全关机后，删除 SD 卡上的：

`atmosphere/contents/4200000000000666/`

然后从 `atmosphere/config/system_settings.ini` 删除整个 `[network_mitm]` 配置段并重新启动。
