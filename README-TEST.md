# Account Link diagnostic v1：一次定位

本版以已成功启动的 resource-v3 为基线：保留 NIM 的临时 PKI fallback，并只为一次 Account Link 定位增加普通 `ssl` 元数据观察。它不是账户认证绕过，也不会读取 TLS/账户内容或改动信任、DNS、身份材料。

## 安装

1. 关机，备份现有4200000000000666模块目录、system_settings.ini和本轮日志。
2. 将诊断包合并到SD根目录。**必须同时替换 exefs.nsp 和 mitm.lst**，不要只复制NSP。路径仍来自 upstream Makefile/NPDM：`/atmosphere/contents/4200000000000666/`。
3. 打开该目录的mitm.lst，必须恰好两行：先 `ssl`，再 `ssl:s`。保留 flags/boot2.flag。
4. 仅合并 `config/account-link-diagnostic.ini.example` 中的 `[network_mitm]` 项；不要覆盖其他设置：

```ini
[network_mitm]
enable_ssl = u8!0x1
targeted_device_pki_mode = u8!0x1
mitm_program_ids = str!0100000000000025
trace_internal_pki = u8!0x1
enable_device_cert_fallback = u8!0x1
device_cert_fallback_program_ids = str!0100000000000025
enable_account_link_diagnostic = u8!0x1
should_mitm_all = u8!0x0
should_dump_ssl_traffic = u8!0x0
should_disable_ssl_verification = u8!0x0
```

5. 保持 emuMMC、Prelude Nextendo模式及当前hosts/信任配置。不要重配Prelude、增加CA、关闭验证或添加其他目标。Prelude重新部署可能清理本模块；如需部署，顺序是Prelude在前、本ZIP在后。
6. 完整重启。先确认能进入HOME，再尝试一次账户关联。不要再安装全系统追踪版。

## 日志

`/atmosphere/logs/network_mitm_observer.log` 每次启动清空，先保存旧文件。新版本应有：

```text
account-link-diagnostic-v1 ports=ssl,ssl:s sessions=16 domains=16 objects=256 workers=2 manager_bytes=...
```

普通 `ssl` 仅允许固定四候选，`ssl:s` 仅允许配置中精确的 NIM；should_mitm_all 即使残留1也不会扩大范围。targeted=0会拒绝所有客户端，不恢复旧模式。

`/network_mitm/internal_pki.log` 继续追加，以 build 和 boot 标记区分。单次点击 Account Link 后，只检查以下无敏感元数据：

```text
account-link-diagnostic-v1 boot build=...
program=... ctx=... CreateContext service=ssl command=0 forward_result=0x...
program=... ctx=... RegisterInternalPki service=ssl command=8 type=... forward_result=0x...
```

这些记录不包含 hostname、TLS/IPC buffer、账户内容、token、证书或私钥。普通 RegisterInternalPki 路径永不 fallback；`0x167B` 仍原样返回，只用于定位。客户端主动 command 12/13 仍透明转发。NIM 的既有成功 fallback 日志仍应保留。

保留的成功路径：原RegisterInternalPki type1返回0x167B → fallback_generate=0 → fallback_import=0 →真实ClientPki ID。原调用成功直接返回原ID；其他错误原样返回。Generate/Import失败不伪造成功，也不重试原身份。RemoveClientPki原样forward。证书CN仍是Nextendo Temporary Client，私钥只在内存且退出时清零。

## 容量和判定

本版针对已观察到的单个NIM客户端，预留16个同时存在的session（包括非domain子对象）、16个domain、256个domain对象。不是可扩展到所有系统程序的通用版本；未经证据和容量审查不要扩大allowlist。每个session的64KiB IPC缓冲区不变。源码有管理器大小检查，打包有NSO BSS<3MiB及对比v2节省至少8MiB的检查。

- 首先：正常进入HOME，且仅NIM被接受。
- PKI创建/导入：v2已实机成功；v3应保持此结果。
- DNS：关联动作出现对应dauth/accounts/baas/aauth查询才算推进；启动hosts列表不算实际查询。
- Nextendo响应、新错误码和最终绑定结果分别记录，不混成一个成功判定。

完成一次定位后，保存日志并按 README-ROLLBACK 移走整个模块目录；不要将本诊断版作为常驻模块，不要扩大候选或随机修改其他模块。

日志无payload/账户内容；PKI日志8MiB封顶。没有新增日志时核对build和日志容量，不要扩大拦截范围。固件/密钥无需放到SD或交给模块。
