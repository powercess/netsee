---
status: Accepted
owners: NetSee maintainers
last_reviewed: 2026-08-16
applies_to: probe operations
references:
  - ../protocol/probe.md
---

# 探针运维

## 环境要求

- Linux VPS，公网 IPv4；可选 IPv6、第二 IP（`-second-ip`，完整 NAT 分类）。
- 默认端口 `8080/8443/8444/8445`；`<1024` 端口需 root 或 `CAP_NET_BIND_SERVICE`。
- 部分 ISP 对探针端口做入站过滤——端口测试结果需结合探针回报解读。

## 构建与部署

```bash
GOOS=linux GOARCH=amd64 go build -o netsee-probe ./cmd/probe
```

- 上传二进制至 VPS；TLS 证书内存自签，无证书文件需管理。
- 探针零落盘：会话注册表内存 + TTL；运行目录可设为只读/tmpfs 验证（ACC-P5-003）。

## systemd unit 示例

```ini
[Unit]
Description=NetSee probe
After=network-online.target

[Service]
ExecStart=/opt/netsee/netsee-probe -port 8080 -tls-port 8443 -udp-port 8444 -nat-port 8445
Restart=on-failure
User=netsee
NoNewPrivileges=true
ProtectSystem=strict
ReadOnlyPaths=/

[Install]
WantedBy=multi-user.target
```

## 防火墙

只放行声明端口；`-second-ip` 未启用时不监听 NAT 异 IP 回包端口以外的任何端口（最小监听面，ACC-P5-004）。

## 升级与回滚

- 探针无持久化状态：替换二进制 + `systemctl restart` 即升级；回滚 = 恢复旧二进制重启。
- 协议破坏性变更需 ADR；`/api/info` 版本不匹配时客户端明确提示。

## 故障处理

- 探针不可达：检查防火墙、ISP 入站过滤、监听状态。
- 并发耗尽：探针有并发与内存上限；压测后评估是否扩容。
