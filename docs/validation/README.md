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
| 2026-08-17 | ACC-P3-001..003 | Linux 7.1.8-zen amd64；本地回环 | `internal/report` 文本+JSON 同一结构（字段一致性单测）、诚实上下文固定行、三层视角 + 每项观测点标注、NAT 原始事实先于判定标签；实跑报告：概览/本机/NAT/总表/TCP/TLS/HTTP/端口/MTU/DNS/信誉/备注 12 段齐全 | 本次 P3 提交；直连对比表随 P4 真实 `--direct` 环境验证 |
| 2026-08-17 | ACC-P4-001、ACC-P4-003 | Linux 7.1.8-zen amd64；本地回环；真实 DoH/信誉 | `bash scripts/e2e-local.sh` 12 项断言全过 + 不可达探针 0s 明确失败；`go test -tags e2e ./internal/client/` 真实网络通过（DoH ok、example.com 无劫持误报、耗时 ≤30s）；跨平台编译 linux/darwin/windows × amd64/arm64 全通过（CI 构建矩阵） | 本次 P4 提交；VPS 冒烟 ACC-P4-002 待探针部署（`bash scripts/vps-smoke.sh <probe-url>`） |
