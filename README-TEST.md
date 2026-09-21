# Account Link fallback v2：ssl:s-only 受控测试

本包保留已验证的 NIM `ssl:s` DeviceClientCertDefault fallback，并保留日志已证明成功的 Account 与 NPNS `ssl:s` type-1 路径。它**不注册 ordinary `ssl` MITM 端口**：上一轮在接受 systemWeb `0100000000001042` 的 ordinary `ssl` 后，network_mitm 自身触发了 Title ID `4200000000000666` 的 Atmosphère `abort (0xFFFE)`。因此本包只测试 system `ssl:s` fallback，不再观察 ordinary `ssl`。

这不是账户认证绕过，不读取 TLS/账户内容，不改 Prelude、DNS、CA、TLS verification 或身份材料。

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

## 预期日志

启动日志应显示：

```text
account-link-fallback-v2 ports=ssl:s sessions=16 domains=16 objects=256 workers=2 manager_bytes=...
```

`network_mitm_observer.log` 只能出现 `SSL SYSTEM` 接受记录；不应出现 ordinary `SSL titleid`。

`/network_mitm/internal_pki.log` 只检查以下 metadata-only 记录：

```text
program=... ctx=... CreateContextForSystem phase=...
program=... ctx=... RegisterInternalPki phase=begin type=1
program=... ctx=... RegisterInternalPki type=1 forward_result=0x0000167B
program=... ctx=... fallback_generate result=0x00000000 origin=ssl_ipc
program=... ctx=... fallback_import result=0x00000000 origin=ssl_ipc
program=... ctx=... RegisterInternalPki phase=complete result=0x00000000
```

成功路径仍是：原始 `RegisterInternalPki(type=1)` 先调用；只有原始结果严格为 `0x0000167B` 时才调用 Generate 与 Import；成功后返回真实 SSL-service PkiId。原始成功和其他错误原样保留；不伪造 PkiId，不重试损坏身份，不改变 `RemoveClientPki`。

## 判定与回滚

- 本包的第一判定：不再出现 `4200000000000666` 的 ordinary `ssl` 相关 panic。
- 第二判定：NIM、Account、NPNS 是否继续完成 system `ssl:s` 的 exact `0x167B` fallback。
- Account/NPNS 的业务最终结果仍需单独记录，不能仅凭 fallback 成功宣称账户已关联。
- 测试结束后按 `README-ROLLBACK.md` 保存日志并移走整个模块目录；不要把该诊断包作为常驻模块。
