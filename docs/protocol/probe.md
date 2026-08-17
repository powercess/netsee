---
status: Accepted
owners: NetSee maintainers
last_reviewed: 2026-08-16
applies_to: probe session protocol
references:
  - ../requirements/functional.md
  - ../requirements/acceptance.md
---

# NetSee 探针会话协议

canonical 定义。客户端与探针不得各自维护漂移类型；字段变更必须同步 `internal/proto/`、本文件与两端兼容测试。

## 会话标识

客户端为每次测量生成 UUID v4（`X-Netsee-Session` / 首条载荷 / SNI 前缀），随每次连接携带：

| 通道 | 传递方式 |
|---|---|
| HTTP | 请求头 `X-Netsee-Session: <uuid>` |
| TCP | 首条 JSON 载荷 `{"session":"<uuid>"}` |
| UDP | 载荷字段 `session` |
| TLS | SNI 前缀 `<session>.n`（`n` 为序号，供多连接归类） |

## UDP 载荷

```json
{"session":"<uuid>","kind":"echo|nat|reach|pmtu"}
```

- `echo`：探针从**同端口**原样回包。
- `nat`：探针从异端口、`-second-ip` 启用时从异 IP 回包，供 RFC 5780 分类。
- `reach`：连通性回报。
- `pmtu`：PMTU 探测回包。

## HTTP API

### GET /api/session/{id}

返回该会话全部观测记录（对方视角总表）：

- 每连接：src ip:port、TTL、协议、时间
- TCP：TCP_INFO 对端指纹（MSS/WScale/SACK/TS/ECN/RTT）
- TLS：JA3/JA4、SNI
- HTTP：完整请求头、注入头（XFF/Via 等透明代理痕迹）

未知/过期会话返回 404（不泄露存在性）。

### GET /api/info

端口自发现响应：HTTP/TLS/UDP/NAT 监听端口、额外端口（测封锁）、第二 IP 可用状态。客户端据此零配置发起测量。

## 注册表

- 内存实现，TTL 清理；不写磁盘。
- 会话与观测记录 1:N；观测追加不可变。

## 兼容性规则

- 新增字段必须向后兼容（客户端忽略未知字段，探针不拒绝未知字段）。
- 破坏性变更（删除/重命名字段、改端口语义）必须新增 ADR 并同步版本。
- 协议版本在 `/api/info` 中声明；客户端与探针版本不匹配时明确提示而非静默降级。
