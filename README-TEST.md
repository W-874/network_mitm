# 测试：损坏 PRODINFO 的 Nextendo SSL Client-PKI PoC

这是实验模块，不是身份修复工具。先测试纯追踪版；只有日志证实目标调用失败后才启用实验版。交叉编译和主机测试不能替代 HOS 22.5.0 / Atmosphère 1.11.2 实机验证。

## 安装前

1. 关机备份 SD 上 `/atmosphere/contents/` 和 `/atmosphere/config/system_settings.ini`，记录已有 `network_mitm` 配置。保存现有 DNS 日志。
2. 保持 **emuMMC、Prelude Nextendo mode、DNS redirect enabled**，保留现有 hosts。不要切换 Nintendo mode，不要主动测试 Nintendo 原站。
3. 先完成 Prelude 配置，再安装本 ZIP。所核对的 Prelude 源码在重新部署 Nextendo 时会删除旧 network_mitm 的启动文件；测试期间不要重新执行 Prelude 的模式应用/更新部署。若执行过，重新检查模块文件是否还在。
4. ZIP 直接合并 SD 根目录。使用 upstream `Makefile`/NPDM 确认的路径 `atmosphere/contents/4200000000000666/`。正常包含 `exefs.nsp`、`mitm.lst`（ssl、ssl:s）、`flags/boot2.flag`。不要移动到猜测的 Title ID。
5. ZIP 不覆盖 `system_settings.ini`，也不附带 DNS hosts、Nintendo 证书、私钥或 IPS。只在现有 `[network_mitm]` 段合并设置，避免重复段/重复键。改配置后完整重启 emuMMC。

## A：先装纯追踪版

文件名：`network_mitm-nextendo-instrumentation.zip`。此二进制不包含 fallback 实现，即使误设 enable_device_cert_fallback=1，也不会合成证书。

```ini
[network_mitm]
enable_ssl = u8!0x1
should_mitm_all = u8!0x1
trace_internal_pki = u8!0x1
enable_device_cert_fallback = u8!0x0
should_dump_ssl_traffic = u8!0x0
should_disable_ssl_verification = u8!0x0
```

不要添加 `custom_ca_public_cert`。追踪模式会抑制 upstream 的 PCAP、CA 注入和 disable-verification 行为，保留 underlying ssl 的验证行为及现有 Prelude 信任配置。该模式增加日志和代理开销，因此不能声称完全没有时序影响。

重启后到 System Settings → 用户 → 关联账户，复现一次 2123-0011，记录大致操作时间、错误码和是否出现其他界面。然后关机取日志：

- `/network_mitm/internal_pki.log`
- 现有 `dns_mitm_debug.log`（保持原位置和原设置）
- `/atmosphere/logs/network_mitm_observer.log`

追踪日志为追加式，时间戳是开机后的单调时钟毫秒；每次模块启动有 boot/build 标记。ctx 编号在每次进程启动后重新开始，必须和 boot 标记、PID 一起看。conn 是模块内连接对象地址，可辅助区分同 context 的不同连接。日志上限 8 MiB，满后停止追加。每轮开始前关机归档/移走旧 internal_pki.log，避免把旧结果当新结果。SD 写失败会放弃日志，不能把“没有日志”推断为“没有 command 8”。

寻找同一个 ctx 的记录（以下为字段示意，不是真实设备结果）：

```text
[时间] program=实际16位ProgramID pid=0x实际PID ctx=N RegisterInternalPki phase=begin type=1(DeviceClientCertDefault)
[时间] program=同一ProgramID pid=同一PID ctx=N RegisterInternalPki type=1 forward_result=0x非零错误
```

还会记录 CreateContext/CreateContextForSystem、CreateConnection/CreateConnectionEx、SetInterfaceVersion、RemoveClientPki、DoHandshake/DoHandshakeGetServerCert。不保存 payload、token、密码、证书或私钥。

**关卡：必须确认本次复现过程中 type=1 且原始 forward_result 非零，并提取 program 字段。** 如果没有 command 8、原调用成功、只有 begin 没有返回，或模块没有启动，先分析这个事实，不要启用 fallback。SetInterfaceVersion 由客户端选择并原样转发；22.x 的当前接口为5，看到旧客户端选择4也不应强行改5。

## B：证据成立后才装实验版

文件名：`network_mitm-nextendo-broken-prodinfo-poc.zip`。默认 fallback=false，allowlist 为空，不允许任何替换。

从 A 的失败记录复制真实 program（不是 PID），只列实际参与失败调用的程序。不要根据“设置/account/DAuth/BAAS”的名字猜 Title ID。

```ini
[network_mitm]
enable_ssl = u8!0x1
should_mitm_all = u8!0x1
trace_internal_pki = u8!0x1
enable_device_cert_fallback = u8!0x1
should_dump_ssl_traffic = u8!0x0
should_disable_ssl_verification = u8!0x0
; 将下面占位符替换为 A 中实际记录的 16 位十六进制 Program ID：
device_cert_fallback_program_ids = str!<从失败日志复制的16位ProgramID>
```

占位符故意不可解析；必须替换才会生效。多个 ID 用逗号分隔，最多16个，每个恰好16位十六进制，无 `0x`、通配符或程序名字。可有空格。空列表、格式错误、重复项、过长/截断、全零 ID 均不会许可任何程序。启动日志 `DevicePkiPolicy` 显示 enabled/allowlist_valid/program_count。fallback 开启时强制 metadata trace；不受 trace_internal_pki=0 影响。

实验版只在允许的程序请求 InternalPki=1 时直接调用同一 underlying context 的 command13，再调用 command12，返回真实 ID。不先调用 command8；不重试 PRODINFO；不伪造成功/ID。其他程序和其他 enum 仍正常 forward。

生成使用 2048-bit RSA、65537、CN=`Nextendo Temporary Client`，有效期由系统生成接口决定（公开接口文档为30天）。证书和私钥仅在内存暂存，导入后擦除；每次符合条件的注册都重新生成，不跨 context 缓存。系统拥有导入对象，RemoveClientPki 原样 forward。

日志示意：

```text
RegisterInternalPki phase=begin type=1(DeviceClientCertDefault)
RegisterInternalPki path=synthetic selected=1
fallback_generate result=0x00000000 origin=ssl_ipc
fallback_import result=0x00000000 origin=ssl_ipc
RegisterInternalPki path=synthetic result=0x00000000 pki_id=真实ID
```

`fallback_allocate` 和 `fallback_validate_lengths` 是本地错误（origin=local）；generate/import 的 Result 是真实服务/IPC 返回。任何失败都返回错误，不继续导入或重试原厂身份。SD 失败可能无法写出错误记录，但不会因此改成成功。

## 按层评估，不把编译成功当绑定成功

| 级别 | 证据 / 下一步 |
|---|---|
| 0 | 2123-0011 且本次流程无相关 DNS：现状，不能单独证明失败位置 |
| 1 | 纯追踪捕获 type=1 的 command8 且真实返回失败；确认 program；否则停止方案 |
| 2 | Generate 和 Import 成功，返回真实 PkiId，原错误点有所变化 |
| 3 | 本次账户动作首次产生 dauth-lp1.ndas.srv.nintendo.net、accounts.nintendo.com、api.accounts.nintendo.com、BAAS 或 aauth 等关联 DNS：关键进展 |
| 4 | Nextendo TLS/API 或登录页响应，即使变成其他错误也有诊断价值 |
| 5 | Nextendo 账户最终成功绑定 |

Level 3 还需与本次动作/时间对应，避免把后台查询当证据；DNS 缓存也可能影响观察。错误变化不等于身份恢复。

如果 Import 成功但仍无相关 DNS，不创建 fake-ID workaround，也不立即打 IPS。先根据日志确定下一个本地边界，再设计 ssl/account/dauth/set:cal/spl:ssl 的 metadata instrumentation。此版本没有这些服务的额外拦截，也没有 Branch B/Branch C。

## 本轮实机结果待填写

- 主机环境：HOS / Atmosphère / emuMMC / Prelude 版本：
- 安装的 ZIP 与 SHA-256：
- Level 1 program / PID / ctx / Result：
- Generate Result / Import Result / PkiId：
- 首个新增关联 DNS 与时间：
- Nextendo 响应 / 新错误码：
- RemoveClientPki Result（如发生）：
- 达到的最高级别：

当前源码只验证了 nx-dauth 的仓库实现假设，不代表已验证线上部署或所有 Nextendo 服务。见 INVESTIGATION.md 的固定 commit 来源。
