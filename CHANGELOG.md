# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与 [语义化版本](https://semver.org/lang/zh-CN/)。

## [0.1.0] - 2026-08-17

首个版本：网络暴露面检测工具（客户端 + 自建探针）。测的是暴露面（沿途节点*能*看到什么），不是实际被监视。

### Added

- 探针 `cmd/probe`：HTTP echo（完整请求头 + TCP_INFO 对端指纹）、TLS 嗅探（JA3/JA4，官方固定向量 + 跨 TCP 分片解析）、UDP echo/NAT 回包（同端口/异端口/异 IP）、会话注册表（内存 + TTL + 上限）、`/api/info` 端口自发现、`/api/session/{id}` 观测拉回、额外端口 reach、`-second-ip` 预留
- 客户端 `cmd/netsee`：本地采集（接口/路由/MTU/DNS）、NAT 类型与对称映射测试（原始事实序列 + 标签 + 前提）、PMTU 探测（`IP_PMTUDISC_DO` + 黑洞检测）、DNS 系统 vs DoH 对比（fake-ip 抑制劫持误报）、IP 信誉（ip-api/ipinfo 降级）、TUN/fake-ip/代理栈路径归因、UDP 归因（TUN 不转发 vs 端口封锁）、`--direct` 直连对比机制
- 报告 `internal/report`：三层视角（出口/路径中间层/终点）+ 每项观测点标注、诚实上下文固定行、原始事实先于判定标签、`--direct` 双栏对比、文本与 JSON 同构输出
- 治理基线：MIT 许可、私有仓库 `powercess/netsee`、分支/提交/发布规范（`CONTRIBUTING.md`）、文档门禁（`check-docs.sh`）、威胁模型、GitHub Actions CI（gofmt/vet/test/check-docs + 6 组合跨平台构建矩阵）
- 验证体系：本地端到端脚本 `scripts/e2e-local.sh`、VPS 冒烟脚本 `scripts/vps-smoke.sh`、e2e 标签真实网络测试、跨平台编译矩阵

### Fixed

- NAT 判定逻辑反向：同 socket 跨目标源端口相同应判定为锥形而非对称式映射（真实 VPS 冒烟发现并双向验证）
- ClientHello 解析器两处越界 panic（fuzz 发现）：cipherLen 与 compLen 读取缺少边界守卫

### Security

- 探针零落盘：会话注册表仅内存 + TTL，只读工作目录可运行（ACC-P5-003，`hardening_test` 子进程验证）
- 最小监听面：仅绑定声明的端口，无额外监听（ACC-P5-004）
- 载荷上限：UDP 2048 / pmtu 9000 / HTTP 头 64KB / ClientHello 64KB，超限静默丢弃
- 畸形输入拒绝：fuzz 目标（UDP 载荷 + ClientHello）+ 并发压力测试——不崩溃、不执行载荷、不创建会话（ACC-P5-001）

### Known / 未验证

- `second-ip` 异 IP 回包路径已实现，需第二公网 IP 验证完整 RFC 5780 分类
- `--direct` 真实直连对比需 TUN 代理环境验证
- 跨平台构建矩阵编译通过；运行时仅 Linux 实测
- 探针端口默认公网开放（无鉴权；按设计零落盘、会话内存 TTL）；生产部署建议按 `docs/operations/probe.md` 用防火墙收口
