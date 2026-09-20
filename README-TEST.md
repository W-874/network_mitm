# NIM-only v2：安装与结果判读

**停止使用 v1 的全系统纯追踪包及旧实验包。**本次直接交付 NIM 定向 fallback，不再要求重复全系统追踪。v2 已交叉编译并通过主机测试，尚未实机验证启动或账户绑定。

## 已有实机证据

提供的 internal_pki.log 两次启动都记录：program=0100000000000025、CreateContextForSystem 成功、RegisterInternalPki type=1 返回 0x167B。v1 同期发生 am / 0100000000000023 的 0x10801 User Break。v2 只针对前述 NIM 调用；现有日志尚不能证明全系统 MITM 是 AM 崩溃的唯一原因，也不能证明这个开机阶段的 PKI 错误就是手动关联账户 2123-0011 的唯一原因。

## 安装一次定向版本

1. 关机，备份 `/atmosphere/contents/4200000000000666/`（若还存在）和 `/atmosphere/config/system_settings.ini`。保存已有日志。
2. 保持 emuMMC、Prelude Nextendo mode 和现有 DNS/信任配置。先完成 Prelude 配置，再装 ZIP；此 Prelude 版本重新部署时会清理 network_mitm。不要切换 Nintendo mode，不修改 hosts、CA 或 IPS。
3. 把 `network_mitm-nextendo-nim-only-v2.zip` 解压并合并到 SD 根目录，替换同路径的旧 exefs.nsp。模块目录仍是 upstream Makefile/NPDM 指定的 `atmosphere/contents/4200000000000666/`，包含 exefs.nsp、mitm.lst 和 flags/boot2.flag。
4. 将下列键合并到现有 `[network_mitm]` 段中。只保留一个同名段和每个键的一份定义；不要用下面内容覆盖整份 system_settings.ini。其余配置（包括已有 account.daemon 设置）保留。

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

`should_mitm_all` 在 targeted mode 下完全被忽略；残留值1也不能扩大接管范围。不要添加 `custom_ca_public_cert`。本版本不抓 PCAP、不加载自定义 CA、不覆盖验证选项。

代码的默认值仍是 fallback=false、两个列表为空；targeted mode 默认 true。漏配新键会导致不接管任何目标，而不会重新启用 v1 的全系统追踪。上面的实际测试配置显式启用 fallback，并且只填入已经在实机日志出现的 NIM ID。

5. 完整重启 emuMMC。先看能否进入 HOME；能正常进入后，再尝试一次账户关联。不需要再次安装纯追踪版。

## 预期日志

只需收集 `/network_mitm/internal_pki.log` 与 `/atmosphere/logs/network_mitm_observer.log`。保留当前 DNS debug 日志以便关联时间。internal_pki.log 追加记录，并以独立 boot/build 标记区分；observer 每次启动会清空旧内容，所以重启前请先保存。时间为单调时钟毫秒，ctx 编号在每次启动后重置。

启动配置记录应显示：

```text
DevicePkiPolicy targeted=1 mitm_valid=1 mitm_count=1 fallback_enabled=1 fallback_valid=1 fallback_count=1 trigger=0x0000167B
```

observer 的 `AcceptMitmImpl SSL... titleid` 应只有 NIM（可能显示为不补前导零的 `100000000000025`）。其他进程不进入本模块；日志 program=0、ctx=0 的 DevicePkiPolicy 是配置标记，不是接管了额外客户端。

成功路径示意（不是实机已成功的记录）：

```text
program=0100000000000025 ... CreateContextForSystem forward_result=0x00000000
program=0100000000000025 ... RegisterInternalPki type=1 forward_result=0x0000167B
program=0100000000000025 ... fallback_generate result=0x00000000 origin=ssl_ipc
program=0100000000000025 ... fallback_import result=0x00000000 origin=ssl_ipc
program=0100000000000025 ... RegisterInternalPki phase=complete result=0x00000000
program=0100000000000025 ... ClientPki pki_id=真实ID
```

此版先调用一次原 command8。原调用成功则返回原 ID、不生成证书；其他错误及其他 enum 均原样返回。仅选中目标的 system context、type=1、原 Result=0x167B 才执行 command13→12。Generate/Import 错误原样返回；没有假成功、fake ID、再次重试原身份或换 context。

日志只保留 context 创建和 PKI 的 Result metadata。不再记录 SetInterfaceVersion、CreateConnection、DoHandshake 或 RemoveClientPki。后者始终执行原始删除；连接 wrapper 只做透明转发。没有这些日志不代表没有发生对应调用。

证书参数为 RSA2048、65537、CN="Nextendo Temporary Client"；系统生成 DER 后按实际长度导入。暂存内存每条退出路径均清零，私钥不写 SD。失败的原注册是否留下阻止导入的 context 状态，仍要看实机 Import Result；不为此提前编写绕过。

日志上限8 MiB，达到上限停止追加；SD写失败放弃记录而不改 SSL Result。没有日志时先检查新配置、模块文件和最新 boot 标记，不要扩大 allowlist。

## 分层判断

| 层级 | 判定 |
|---|---|
| 启动门槛 | 能正常进入系统，且接管客户端只有 NIM；v2 尚未验证 |
| Level 1 | NIM system context 的 type=1 原调用0x167B：已有两次开机日志证据 |
| Level 2 | Generate/Import 成功并返回真实 ID；还需实机验证 |
| Level 3 | 本次相关流程出现新的 dauth/accounts/baas/aauth DNS；需结合时间和缓存判断 |
| Level 4 | Nextendo 页面或 TLS/API 有响应，即使出现新错误码也有价值 |
| Level 5 | Nextendo 账户绑定完成 |

若依然开机 fatal，保存新的 fatal/crash `.log` 和两个模块日志，关机移走整个模块目录恢复启动；不要开关其他一批模块碰运气。v2 可能缩小影响范围，但不能承诺消除未知的资源限制原因。

若 PKI 导入成功但没有关联流程推进，保留新错误码和 DNS 日志，再定位下一个本地边界；不恢复全系统 MITM，不直接上 fake-ID 或 IPS。

## 后续扩展

两个 ID 列表都支持最多16个逗号分隔、恰好16位的十六进制 ID（不带0x；可有空格）。空列表、重复项、全零、非法字符、截断或超长列表均不会许可任何前缀。

新的 ID 必须有额外的定向证据才能加入两个列表。v2 有意不观察未接管程序，因此不能靠本模块日志自动发现所有其他调用者；需要先从具体错误报告/其他明确证据提出目标，再定向诊断。增加 ID 不会自动把普通 ISslContext 纳入 fallback；若后续证据走普通 context，需要另行审查实现。这一轮只修改已观察到的 ISslContextForSystem。
