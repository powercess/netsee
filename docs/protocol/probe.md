---
status: Accepted
owners: NetSee maintainers
last_reviewed: 2026-08-17
applies_to: probe session protocol
references:
  - ../requirements/functional.md
  - ../requirements/acceptance.md
---

# NetSee 探针会话协议

canonical 定义。客户端与探针不得各自维护漂移类型；字段变更必须同步 `internal/proto/`、本文件与两端兼容测试。观测记录字段以 `internal/proto/types.go` 为代码级事实源。

## 会话标识

客户端为每次测量生成 UUID v4（`X-Netsee-Session` / 首条载荷 / SNI 前缀），随每次连接携带：

| 通道 | 传递方式 |
|---|---|
| HTTP | 请求头 `X-Netsee-Session: <uuid>` |
| TCP（额外端口） | 首条 JSON 载荷 `{"session":"<uuid>","kind":"reach"}` |
| UDP | 载荷字段 `session` |
| TLS | SNI 前缀 `<session>.n`（`n` 为序号，供多连接归类） |

非法/缺失会话标识的连接不创建会话、不记录观测（仅 HTTP echo 返回 `{"ok":false,...}` 语义的拒绝）。

## UDP 载荷

```json
{"session":"<uuid>","kind":"echo|nat|reach|pmtu"}
```

- `echo` / `reach` / `pmtu`：探针从**同端口**原样回包。
- `nat`：探针从 NAT 端口回包；`-second-ip` 启用时从第二 IP 回包，供 RFC 5780 分类。
- `pmtu` 载荷允许更大的 `data` 字符串字段（客户端用其填充探测字节），上限 `-max-udp-pmtu`（默认 9000）；其余 kind 上限 `-max-udp`（默认 2048），超限静默丢弃。
- `reply_from` 相对到达端口：同端口回包 `same`，异端口 `other-port`，异 IP `other-ip`。
- **NAT 端口也接收并记录入站 datagram**（`dst_port`= NAT 端口）：客户端据此比较同一 socket 发往不同目标端口时探针观测到的源端口（对称映射检测）。
- 未知 kind / 非法 JSON / 非法会话：不回复、不记录。

## HTTP API

### GET /api/info

端口自发现响应（`proto.Info`）：HTTP/TLS/UDP/NAT 监听端口、额外端口、`second_ip` 可用状态、`max_udp_pmtu` 载荷上限与协议版本。客户端据此零配置发起测量。协议版本不匹配时客户端必须明确提示。

### GET /api/session/{id}

返回该会话全部观测记录（对方视角总表，`[]*proto.Obs`）：

- 每连接：src ip:port、dst port、协议、时间
- TCP（HTTP/额外端口/TLS 端口）：TCP_INFO 对端指纹（MSS/WScale/SACK/TS/ECN/RTT）
- TLS：JA3/JA4、SNI
- HTTP：完整请求头（含 Host 与透明代理注入头如 XFF/Via）
- UDP：kind、reply_from（`same`/`other-port`/`other-ip`）、载荷长度
- TTL：仅 UDP 采集（Linux `IP_RECVTTL`，无需 root）；TCP TTL 需 raw socket，属非目标，不采集

未知/过期会话一律 404，不泄露存在性。

### 其他请求

非 `/api/*` 的 HTTP 请求作为 echo 观测：记录完整请求头与 TCP_INFO，返回 `{"ok":true,"session":...,"obs_id":...}`。

### TLS 端口

嗅探模式：只读握手前 ClientHello（跨 TCP 分片累积解析），记录 JA3/JA4/SNI 后关闭连接。**不完成握手、不发送任何字节、无需证书**（探针不承担正式 PKI）。

### 额外 TCP 端口

读取首条 JSON 载荷（≤4KB，带读超时），记录 `kind=tcp` 观测，应答 `{"ok":true}`（载荷非法则 `{"ok":false}`）。

## 注册表

- 内存实现，TTL 清理（默认 5 分钟，可配），不写磁盘。
- 会话上限默认 10000（超出驱逐最旧）；单会话观测上限 4096。
- 观测追加不可变。

## 兼容性规则

- 新增字段必须向后兼容（客户端忽略未知字段，探针不拒绝未知字段）。
- 破坏性变更（删除/重命名字段、改端口语义）必须新增 ADR 并同步版本。
- 协议版本在 `/api/info` 中声明；客户端与探针版本不匹配时明确提示而非静默降级。
