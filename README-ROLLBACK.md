# 回滚

1. 完整关机，取出 SD。不要仅退出设置页面：sysmodule 会持续运行到关机/重启。
2. 有原模块备份：恢复 `/atmosphere/contents/4200000000000666/` 原目录；原先没有该模块：移走本次添加的整个目录（包括 mitm.lst 和 boot2.flag）。只取消 boot2.flag 却留下 MITM 声明可能造成启动/服务等待，完整恢复目录最稳妥。
3. 恢复备份的 `/atmosphere/config/system_settings.ini`，或精确撤回本次 `[network_mitm]` 修改。不要误删其他配置节。
4. 保留现有 Prelude Nextendo hosts、DNS 重定向和原本信任文件；无需切换 Nintendo mode。本项目未改这些文件。
5. 归档 `/network_mitm/internal_pki.log` 和 `/atmosphere/logs/network_mitm_observer.log`，再重启 emuMMC。

如果只是停止 fallback、继续定位：将 enable_device_cert_fallback 设为0并清空 allowlist，或重新安装纯追踪版，然后完整重启。若发生开机异常，在关机状态直接完成上述 SD 回滚。

临时证书/密钥没有写入 SD，也没有修改 PRODINFO/NAND；删除日志不是密钥擦除步骤。底层 SSL context 持有的临时 PKI 随 context 删除/系统重启释放。本项目没有 donor 身份、fake PKI ID、eTicket 修改或 SSL NSO IPS 可回滚。
