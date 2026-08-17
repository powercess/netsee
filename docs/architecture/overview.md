---
status: Accepted
owners: NetSee maintainers
last_reviewed: 2026-08-16
applies_to: architecture overview
references:
  - ../requirements/README.md
---

# NetSee 总体架构

## 组件与数据流

```
┌──────────────┐   会话协议(JSON)   ┌──────────────────┐
│  netsee CLI  │ ◄───────────────► │  netsee-probe    │
│  (本机)       │   TCP/UDP/TLS/HTTP │  (VPS)           │
└──────────────┘                    └──────────────────┘
      │ 本地自检                               │ 记录对方视角事实:
      │ 接口/路由/MTU/DNS/PMTU                 │  src ip:port, TTL,
      │                                      │  TCP选项, JA3/JA4,
      │ 外部查询                              │  HTTP头, NAT行为
      └─ ip-api / ipinfo (IP 信誉)            │
```

- 探针只记录事实；客户端做本地采集 + 汇总判定。
- 判定结论标注置信度与前提（如"单 IP 无法区分对称/端口受限映射"）。
- 探针经 `/api/session/{id}` 与 `/api/info` 提供零配置发现；会话注册表内存实现 + TTL 清理。

## 模块边界

| 模块 | 职责 | 依赖方向 |
|---|---|---|
| `cmd/probe` | 探针入口：参数、监听编排 | → internal/probe |
| `cmd/netsee` | 客户端入口：参数、流程编排 | → internal/client, report |
| `internal/proto` | `Obs`/`Store`/`Info` 共享类型 | 无（被两端引用） |
| `internal/probe` | HTTP/TCP/UDP/TLS 观测、JA3/JA4、TCP_INFO | → proto, x/net, x/sys |
| `internal/client` | 本地采集、NAT/PMTU/DNS/信誉、TUN 归因 | → proto, x/net, x/sys |
| `internal/report` | 报告结构 + 文本/JSON 渲染 | → proto |

`internal/proto` 是两端唯一共享类型来源：协议字段变更必须同步修改一处、由 `go test` 约束（见 `../protocol/probe.md` 兼容性规则）。

## 部署形态

- 客户端：本机单二进制，无后台进程、无常驻。
- 探针：VPS 单二进制，默认端口 `8080/8443/8444/8445`，可选 `-second-ip`（完整 NAT 分类）。
- 探针 TLS 证书内存自签（只做指纹嗅探，不承担正式 PKI）。
- 运维细节见 `../operations/probe.md`。

## 关键设计约束

- 中间层不专门实现：终点 echo 已覆盖中间层 95%+ 观测能力；v2 可选 CONNECT 模式复用 `proto.Obs`。
- TUN 归因是正确性要求：默认路由接口名、fake-ip 段、代理栈指纹比对，缺一不得把代理出口当作本机直连。
- 依赖仅 `x/net` + `x/sys`；避免引入 TLS 栈、抓包库等重依赖。
