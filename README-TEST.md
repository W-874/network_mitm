# resource-v3：安装和验证

这是针对启动资源负担的修复版。v2 实机已经证明 NIM 的临时 PKI 生成、导入成功；本轮保留这条路径，修复过大的固定资源预留。AM 对应固件已核对：失败发生在请求启动 GRC 时，详见 CRASH-ANALYSIS.md。v3 尚未实机验证启动成功。

## 安装

1. 关机，备份现有4200000000000666模块目录、system_settings.ini和本轮日志。
2. 将 network_mitm-nextendo-resource-v3.zip 合并到SD根目录。**必须同时替换 exefs.nsp 和 mitm.lst**，不要只复制NSP。路径仍来自 upstream Makefile/NPDM：`/atmosphere/contents/4200000000000666/`。
3. 打开该目录的mitm.lst，应该只有一行 `ssl:s`，不再有 `ssl`。保留 flags/boot2.flag。
4. 你本次提交的v2配置已经正确，可以直接保留。下面是完整的相关段落，供核对；不要覆盖其他设置：

```ini
[network_mitm]
enable_ssl = u8!0x1
targeted_device_pki_mode = u8!0x1
mitm_program_ids = str!0100000000000025
trace_internal_pki = u8!0x1
enable_device_cert_fallback = u8!0x1
device_cert_fallback_program_ids = str!0100000000000025
should_mitm_all = u8!0x0
should_dump_ssl_traffic = u8!0x0
should_disable_ssl_verification = u8!0x0
```

5. 保持 emuMMC、Prelude Nextendo模式及当前hosts/信任配置。不要重配Prelude、增加CA、关闭验证或添加其他目标。Prelude重新部署可能清理本模块；如需部署，顺序是Prelude在前、本ZIP在后。
6. 完整重启。先确认能进入HOME，再尝试一次账户关联。不要再安装全系统追踪版。

## 日志

`/atmosphere/logs/network_mitm_observer.log` 每次启动清空，先保存旧文件。新版本应有：

```text
resource-v3 port=ssl:s sessions=16 domains=16 objects=256 workers=2 manager_bytes=...
AcceptMitmImpl SSL SYSTEM titleid: 100000000000025
```

普通ssl没有注册；should_mitm_all即使残留1也不会扩大范围。targeted=0会拒绝所有客户端，不恢复旧模式。

`/network_mitm/internal_pki.log` 继续追加，以build和boot标记区分。保留NIM PKI日志，并新增：

```text
Resources stage=before_register scope=self_resource_group kind=memory_bytes used=... limit=... remaining=...
Resources stage=serving scope=self_resource_group kind=threads used=... limit=... remaining=...
Resources stage=after_pki scope=self_resource_group kind=sessions used=... limit=... remaining=...
```

也记录events、transfer_memories。memory_bytes单位字节，其余是数量。这是模块所属资源组的非原子快照，不是AM私有堆大小；不修改系统额度。查询失败只记录Result。program=0/ctx=0是诊断记录，不是接管了额外程序。

保留的成功路径：原RegisterInternalPki type1返回0x167B → fallback_generate=0 → fallback_import=0 →真实ClientPki ID。原调用成功直接返回原ID；其他错误原样返回。Generate/Import失败不伪造成功，也不重试原身份。RemoveClientPki原样forward。证书CN仍是Nextendo Temporary Client，私钥只在内存且退出时清零。

## 容量和判定

本版针对已观察到的单个NIM客户端，预留16个同时存在的session（包括非domain子对象）、16个domain、256个domain对象。不是可扩展到所有系统程序的通用版本；未经证据和容量审查不要扩大allowlist。每个session的64KiB IPC缓冲区不变。源码有管理器大小检查，打包有NSO BSS<3MiB及对比v2节省至少8MiB的检查。

- 首先：正常进入HOME，且仅NIM被接受。
- PKI创建/导入：v2已实机成功；v3应保持此结果。
- DNS：关联动作出现对应dauth/accounts/baas/aauth查询才算推进；启动hosts列表不算实际查询。
- Nextendo响应、新错误码和最终绑定结果分别记录，不混成一个成功判定。

若仍fatal，保存新fatal/crash报告、两个模块日志与原有DNS日志，按README-ROLLBACK移走整个模块目录。新资源计数和已经定位的GRC启动调用点将限定下一步排查；不要重装旧包或随机关闭其他模块。

日志无payload/账户内容；PKI日志8MiB封顶。没有新增日志时核对build和日志容量，不要扩大拦截范围。固件/密钥无需放到SD或交给模块。
