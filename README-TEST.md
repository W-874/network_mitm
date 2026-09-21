# Account Link fallback v2：安装与受控测试

[English install guide](README-TEST.en.md) · **中文**

> **安装前必读：** [README-ROLLBACK.md](README-ROLLBACK.md) · 本指南只适用于 HOS 22.5.0 / Atmosphère 1.11.2 / emuMMC。

本包只注册 `ssl:s`，不注册 ordinary `ssl`。它仅针对 NIM、Account、NPNS 三个明确 Program ID，并只对 `InternalPki` type 1、原始错误精确为 `0x0000167B` 的情况执行 original-first fallback。不会修改 Prelude、DNS、CA、TLS verification 或设备身份。

## 安装

1. 完整关机，备份现有 `/atmosphere/contents/4200000000000666/`、`system_settings.ini` 和本轮日志。
2. 将本包合并到 SD 根目录。**必须同时替换 `exefs.nsp` 和 `mitm.lst`**，路径为 `/atmosphere/contents/4200000000000666/`；保留 `flags/boot2.flag`。
3. `mitm.lst` 必须恰好只有一行：

   ```text
   ssl:s
   ```

4. 仅合并下面完整的 `[network_mitm]` 区块；不要覆盖其他设置段：

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

5. 保持 emuMMC、Prelude Nextendo 模式及现有 hosts/信任配置。不要增加 CA、关闭 TLS verification、修改 DNS 或添加其他 Program ID。
6. 完整重启。先确认可进入 HOME，再只进行一次 Nintendo Account 关联动作；不要安装旧的 ordinary `ssl` 诊断包。

## 预期结果

启动日志应显示 `account-link-fallback-v2 ports=ssl:s`。`network_mitm_observer.log` 只能出现 `SSL SYSTEM` 接受记录，不应出现 ordinary `SSL titleid`。

只检查 metadata-only 的 `internal_pki.log` 记录；不要记录或上传证书、私钥、token、密码、TLS payload 或账户内容。成功路径是：先调用原始 `RegisterInternalPki`，仅在 type 1 且原始结果为 `0x0000167B` 时调用 Generate/Import，并返回真实 SSL-service PkiId。

## 已知结果与限制

目标环境已确认 NIM、Account、NPNS fallback 成功、Account Link 成功，以及 Mario Kart 8 Deluxe 可联机。删除已关联用户仍会报 `2002-0001`；本版本不支持、也不宣称支持该操作。

不要测试 Nintendo production endpoint。测试结束后按 [README-ROLLBACK.md](README-ROLLBACK.md) 回滚，并移走整个模块目录。
