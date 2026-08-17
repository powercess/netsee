---
status: Accepted
owners: NetSee maintainers
last_reviewed: 2026-08-16
applies_to: netsee evolution plan
references:
  - requirements/README.md
  - requirements/acceptance.md
  - protocol/probe.md
---

# NetSee 演进路线与实施方案

本文件是 NetSee 阶段演进的唯一事实源：定义每个阶段的交付物、验收项、验证方法与出口条件。阶段按依赖顺序推进，验收项以 `docs/requirements/acceptance.md` 的稳定 ID 为准。

## 阶段总览

| 阶段 | 名称 | 核心交付 | 出口条件 |
|---|---|---|---|
| P0 | 治理基线 | 文档约束、许可证、CI、远端 | 全部 ACC-P0 通过 |
| P1 | 探针（观测点） | HTTP/TCP/UDP/TLS 观测 + 会话协议 | 全部 ACC-P1 通过 |
| P2 | 客户端（本地采集） | 本地事实 + 判定 + TUN 归因 | 全部 ACC-P2 通过 |
| P3 | 报告 | 文本/JSON + 诚实上下文 + 对比 | 全部 ACC-P3 通过 |
| P4 | 端到端与验证 | e2e + VPS 冒烟 + 固定向量单测 | 全部 ACC-P4 通过 |
| P5 | 加固与发布 | 拒绝路径、资源边界、v0.1.0 | 全部 ACC-P5 通过 |
| V2 | 可选扩展 | CONNECT 中间层、`--direct` 完整化、常驻监测 | 单独确认后立项 |

## P0 治理基线

目标：仓库可协作、文档有唯一事实源、门禁可执行。

交付物：

- MIT `LICENSE` 与 `docs/governance/licensing.md`（许可决策记录）
- 文档约束套件：`CONTRIBUTING.md`、`SECURITY.md`、`CODE_OF_CONDUCT.md`、`AGENTS.md`、Issue/PR 模板
- `docs/` 事实源结构（`docs/README.md` 定义状态机与稳定 ID）
- `scripts/check-docs.sh` 文档门禁 + `.github/workflows/ci.yml`
- 私有远端 `powercess/netsee`；`main`/`dev` 分支保护（GitHub Free 限制无法在 private 仓库启用，见 RISK-REPO-001）

验收：`ACC-P0-001` 至 `ACC-P0-003`。

验证：本地运行 `bash scripts/check-docs.sh`；推送后确认 CI 与分支保护生效。

依赖：无。

出口条件：远端可推、门禁脚本通过；分支保护因 GitHub Free 限制暂以书面规则执行（RISK-REPO-001）。

## P1 探针（观测点）

> 状态：已完成（2026-08-17）。ACC-P1-001..007 本地回环通过；验证记录见 [validation/README.md](validation/README.md)。VPS 冒烟与 second-ip 异 IP 回包验证归 P4。

目标：探针可运行在公网 VPS，对每个会话回报"对方视角"原始事实；协议先行并在本地回环端到端走通。

交付物：

- `internal/proto/`：`Obs`（观测记录）、`Store`（会话注册表，内存 + TTL）、`Info`（端口自发现响应）
- `internal/probe/`：
  - `server.go` HTTP/TCP/UDP/TLS 监听编排（默认端口 8080/8443/8444/8445，可配置）
  - `tls.go` 握手前 ClientHello 嗅探（跨分片累积解析）
  - `ja3.go` JA3/JA4 指纹计算（固定测试向量）
  - `tcpinfo.go` TCP_INFO 对端指纹（MSS/WScale/SACK/TS/ECN/RTT）
- `cmd/probe/` 入口 + 命令行参数（端口、`-second-ip` 预留）
- 协议实现与测试：会话 UUID 传递（HTTP `X-Netsee-Session` / TCP/UDP 首条 JSON / TLS SNI 前缀）、UDP 同端口回包、NAT 异端口/异 IP 回包、`GET /api/session/{id}`、`GET /api/info`
- 依赖引入：`golang.org/x/net`、`golang.org/x/sys`

验收：`ACC-P1-001` 至 `ACC-P1-006`。

验证：本地起探针（`go run ./cmd/probe`），用 curl/`nc`/`openssl s_client` 逐项触发并比对观测；`go test ./internal/probe/...` 跑 JA3 固定向量与跨分片用例。

依赖：Go 工具链安装（开发机）。

出口条件：本地回环端到端全链路可观测、单测全绿；探针部署到 VPS 由 P4 冒烟验证。

## P2 客户端（本地采集）

> 状态：已完成（2026-08-17）。ACC-P2-001..009 本地回环通过，验证记录见 [validation/README.md](validation/README.md)。真实 NAT/TUN 场景与直连对比归 P4 VPS 验证。

目标：客户端零配置采集本机事实，执行判定测试，正确归因 TUN/代理路径。

交付物：

- `internal/client/`：
  - `local.go` 接口/路由/MTU/resolv.conf 采集
  - `session.go` 探针连接 + 端口自发现（`/api/info`）
  - `nat.go` NAT 类型与对称映射测试（多 socket 映射稳定性 + 端口/IP 过滤）
  - `pmtu.go` 路径 MTU（Linux `IP_PMTUDISC_DO` 递增载荷）
  - `dns.go` 系统解析器 vs DoH 对比（DNS 劫持/分流检测）
  - `reputation.go` ip-api/ipinfo 信誉查询（`IPINFO_TOKEN` 可选）
- 路径归因层（v1 必需）：TUN 识别（默认路由接口名）、fake-ip 识别（`198.18.0.0/15`）、代理程序指纹推断（探针观测比对已知代理栈；未匹配只标"代理出口"）、UDP 归因（先排除 TUN 不转发）
- `--direct` 对比模式：探针 IP 加直连路由绕过 TUN，输出直连 vs 代理出口双栏；需 root，部分 TUN 程序覆盖路由守卫时明确提示失败

验收：`ACC-P2-001` 至 `ACC-P2-005`。

验证：无代理与 TUN 代理两种环境下分别运行，比对 `ip`/`resolvectl` 等系统命令输出；构造 fake-ip 环境验证不误报。

依赖：P1 探针可运行（本地或 VPS）。

出口条件：本地采集与判定在真实环境输出可信、TUN 场景归因正确。

## P3 报告

> 状态：已完成（2026-08-17）。文本与 JSON 报告同一结构（ACC-P3-002），诚实上下文行与三层视角标注齐全（ACC-P3-001），判定事实先于标签（ACC-P3-003）；直连对比渲染随 P4 真实环境验证。

目标：三层视角（出口 / 路径中间层 / 终点）结构化呈现，内置诚实上下文，支持对比。

交付物：

- `internal/report/`：报告结构 + 文本渲染 + JSON 渲染
- 概览区固定一行诚实上下文："沿途节点有*能力*看到以下信息；是否真的在看取决于具体服务商。本工具测的是暴露面，不是实际被监视。"
- 报告顺序：概览（公网 IP v4/v6、出口数、NAT 类型、RTT、突出发现）→ 本机网络 → 对方视角总表 → TCP 指纹 → TLS 指纹 → HTTP 视角 → 端口连通性 → 路径 MTU → DNS → IP 信誉
- 判定结论标注置信度与前提；原始事实先于判定标签
- TUN 路径归因标注；`--direct` 双栏对比

验收：`ACC-P3-001` 至 `ACC-P3-003`。

验证：本地探针全流程生成报告，人工核对字段；`--json` 与文本报告字段一致性用脚本断言。

依赖：P1、P2。

出口条件：文本与 JSON 报告字段一致、诚实上下文与归因标注齐全。

## P4 端到端与验证

> 状态：已完成（2026-08-17）。e2e-local.sh 断言通过（ACC-P4-001/003）、跨平台构建矩阵进 CI、e2e 标签真实网络测试、**VPS 冒烟通过（ACC-P4-002）**：真实 HK VPS 全流程验证（对称 NAT、PMTU 1500、TLS 嗅探、端口连通性、DNS 诚实降级、IP 信誉），并修正 NAT 判定逻辑反向 bug。剩余 Unverified：`second-ip` 异 IP 回包（需第二 IP）与 `--direct` 真实直连对比（需 TUN 环境）——归 P5/V2。

目标：全链路可复现验证，包括真实 VPS 冒烟与指纹解析的确定性。

交付物：

- e2e 脚本：本地起探针跑全流程（HTTP/TCP/UDP/TLS/NAT/PMTU/DNS/信誉），输出报告并断言关键字段
- JA3/JA4 固定测试向量：真实浏览器 ClientHello 抓包固化；跨 TCP 分片用例
- VPS 冒烟清单：默认端口、`/api/info` 自发现、`/api/session/{id}` 拉取、TCP_INFO 与 TLS 嗅探在真实公网路径下可用
- 集成测试标记：不依赖真实公网的测试默认在单测跑；公网相关标记为集成测试

验收：`ACC-P4-001`、`ACC-P4-002`。

验证：`bash scripts/e2e-local.sh`（或等价命令）全绿；VPS 冒烟记录写入 `docs/validation/`。

依赖：P1–P3；可用的 VPS。

出口条件：本地与公网两条路径都有可追踪验证记录。

## P5 加固与发布

> 状态：已完成（2026-08-17）。畸形载荷 fuzz（发现并修复 2 处越界 panic）、并发压力、零落盘与最小监听面子进程验证（ACC-P5-001/003/004）、`-version` 标志与 CHANGELOG；v0.1.0 发布提升 PR 与签名 tag 随后。

目标：拒绝路径与资源边界完备，产出 v0.1.0。

交付物：

- 探针加固：载荷长度与 schema 严格校验、并发上限、会话注册表内存上限、读写超时、优雅关闭
- 客户端加固：网络操作全局超时、报告本地生成不上传、错误路径（探针不可达、无公网、权限不足）明确提示
- 发布门禁：版本号、变更日志、构建矩阵（linux/darwin/windows × amd64/arm64）、签名 `v0.1.0` tag、发布说明含兼容性与未验证平台

验收：`ACC-P5-001`、`ACC-P5-002`。

验证：畸形/超长载荷 fuzz 冒烟不崩溃；release 构建 + tag 创建。

依赖：P1–P4。

出口条件：发布门禁全过，v0.1.0 产出。

## V2 可选扩展（不承诺）

- CONNECT 中间层模式：探针加代理端口，客户端 `-via` 开关，输出"直连 vs 穿透"对比——复用 `proto.Obs`，预计百来行
- `--direct` 完整化：处理代理程序覆盖路由守卫的场景
- 常驻监测形态：定期测量 + 变化告警（单独确认后立项）

## 风险清单

| ID | 风险 | 缓解 |
|---|---|---|
| RISK-PROBE-001 | 探针端口被 ISP 入站过滤 | 多端口自发现 + 客户端比对探针回报解读 |
| RISK-REPORT-001 | 指纹保质期短（JA3 因 uTLS/浏览器更新失效） | 对比优先于绝对值 |
| RISK-NAT-001 | 单 IP 探针 NAT 分类不完整 | 报告显式标注前提；`-second-ip` 预留 |
| RISK-TUN-001 | TUN 归因依赖代理栈指纹比对，未知代理不匹配 | 未匹配只标"代理出口"不点名 |
| RISK-TOOLCHAIN-001 | 开发机缺 Go 工具链 | P1 前置安装（`pacman -S go`） |
| RISK-REPO-001 | GitHub Free 套餐 private 仓库不支持分支保护（required reviews/checks 需 Pro） | 书面规则（CONTRIBUTING）自律执行；升级 Pro 或转公开后启用强制保护 |

## 里程碑记录

| 日期 | 事件 |
|---|---|
| 2026-08-16 | 需求方案冻结（`requirements/README.md`）；P0 启动 |
| 2026-08-16 | P0 治理基线推送 `powercess/netsee`（private）；分支保护因 Free 限制降级为书面规则 |
| 2026-08-17 | P1 探针实现完成：HTTP/TCP/UDP/TLS 观测、会话协议、JA3/JA4（官方固定向量 + 跨分片）、本地 e2e 全绿 |
| 2026-08-17 | P2 客户端实现完成：本地采集、NAT/PMTU/DNS/信誉测量、TUN/fake-ip 归因、--direct 机制、cmd/netsee CLI；本地回环全链路验证通过 |
| 2026-08-17 | P3 报告实现完成：internal/report 三层视角结构（文本+JSON 同构）、诚实上下文行、事实先于判定、直连对比渲染；客户端观测扩展完整 TCP 指纹与 HTTP 头 |
| 2026-08-17 | P4 本地端到端：e2e-local.sh 断言通过、跨平台构建矩阵进 CI、e2e 标签真实网络测试、不可达快速失败；VPS 冒烟脚本就绪待部署 |
| 2026-08-17 | P4 VPS 冒烟通过（HK 222.167.130.199）：真实 NAT 判定、TLS 嗅探、PMTU、端口连通性、DNS 降级、IP 信誉全链路验证；修正 NAT 判定逻辑反向 bug；探针静态编译（CGO_ENABLED=0）经验入运维文档 |
| 2026-08-17 | P5 加固：fuzz 修复 2 处越界 panic、并发压力、零落盘/最小监听面验证、-version 与 CHANGELOG；v0.1.0 发布 |
