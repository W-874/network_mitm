# NIM-only v2 回滚

1. 完整关机，取出 SD；保存本轮 `/network_mitm/internal_pki.log`、`/atmosphere/logs/network_mitm_observer.log`，以及本轮 fatal/crash `.log`（如果产生）。
2. 将整个 `/atmosphere/contents/4200000000000666/` 移到电脑。不要只移走 boot2.flag 而保留 mitm.lst。
3. 恢复安装前 system_settings.ini 的 `[network_mitm]` 配置。不要改其他配置段、Prelude hosts、DNS 或信任文件。
4. 重启 emuMMC。若安装前并无本模块，保持这个目录不在 contents 内即可。不要恢复已导致启动故障的 v1 全系统追踪包。

仅想关掉 fallback 时，可设 enable_device_cert_fallback=0 后完整重启；它仍会对明确列出的 NIM 做定向日志，不会重新扫描全系统。如要完全撤掉模块，采用上面的目录移除方式。

没有修改 NAND、PRODINFO、序列号、eTicket key、固件 ExeFS 或 IPS。临时证书/key 没有写 SD；系统 context 的临时对象随销毁或重启释放。
