# Account Link fallback v2 回滚

1. 完整关机，取出 SD；保存本轮 `/network_mitm/internal_pki.log`、`/atmosphere/logs/network_mitm_observer.log`，以及本轮 fatal/crash `.log`（如果产生）。
2. 将整个 `/atmosphere/contents/4200000000000666/` 移到电脑。不要只移走 boot2.flag 而保留 mitm.lst。
3. 恢复安装前 system_settings.ini 的 `[network_mitm]` 配置。不要改其他配置段、Prelude hosts、DNS 或信任文件。
4. 重启 emuMMC。若安装前并无本模块，保持这个目录不在 contents 内即可。不要恢复已导致启动故障的 v1/v2 失败版本。

一次定位完成后，完整移走模块目录并恢复安装前的 `[network_mitm]` 设置；尤其保持或删除 `enable_account_link_diagnostic` 均可，但本包源码不注册 ordinary `ssl`；恢复安装前配置，不要保留诊断包作为常驻模块。仅想关掉 NIM fallback 时，可设 enable_device_cert_fallback=0 后完整重启；它仍不会重新扫描全系统。

没有修改 NAND、PRODINFO、序列号、eTicket key、固件 ExeFS 或 IPS。临时证书/key 没有写 SD；系统 context 的临时对象随销毁或重启释放。
