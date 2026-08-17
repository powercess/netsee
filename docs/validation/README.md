---
status: Accepted
owners: NetSee maintainers
last_reviewed: 2026-08-17
applies_to: validation evidence
references: []
---

# 实测证据

本目录存放可追踪的验证记录：真实结果只写在这里，目标值/预期/实测值必须分开。

## 记录约定

每条验证记录必须包含：

- 环境：OS、内核、硬件、网络路径（含 TUN/代理状态）
- 命令与原始数据位置
- 结果与对应验收项（ACC-* ID）
- 限制与有效期

## 当前记录

| 日期 | 验收项 | 环境 | 结果 | 记录位置 |
|---|---|---|---|---|
| 2026-08-17 | ACC-P1-001..007 | Linux 7.1.8-zen amd64；本地回环 127.0.0.1 | `go test -race ./...` 全绿；二进制冒烟：`/api/info` 自发现一致、HTTP echo 拉回完整请求头 + TCP_INFO（mss=32768, wscale/sack/ts）、未知/过期会话 404、UDP echo 同端口回包、NAT 异端口回包（源端口= nat 端口）、真实 openssl ClientHello → JA3/JA4（SNI 前缀会话提取） | P1 提交（PR #4）；`second-ip` 异 IP 回包路径待 P4 VPS 验证 |
| 2026-08-17 | ACC-P2-001..009 | Linux 7.1.8-zen amd64；本地回环 127.0.0.1；无 root | `go test -race ./...` 全绿；`netsee -probe http://127.0.0.1:18080` 实跑：本地采集（默认路由 ens33/lo、MTU 1500）、NAT 直连标签 + 原始事实序列、PMTU 9028（达探针上限）、DNS 系统 vs DoH 一致（各 4 条）、四端口连通性与探针回报全部一致、信誉不可用降级、`--direct` 回环降级提示、诚实上下文行 | 本次 P2 提交；真实 NAT/TUN 场景、直连对比、VPS 冒烟归 P4 |
