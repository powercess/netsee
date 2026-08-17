---
status: Accepted
owners: NetSee maintainers
last_reviewed: 2026-08-16
applies_to: acceptance criteria
references:
  - functional.md
  - non-functional.md
  - ../roadmap.md
---

# NetSee 验收项

验收项按阶段组织（见 `../roadmap.md`）。每项必须可执行、可观察；验证记录写入 `../validation/`。

## P0 治理基线

### ACC-P0-001：文档门禁通过
`bash scripts/check-docs.sh` 本地执行无错误输出。

### ACC-P0-002：CI 工作流有效
`.github/workflows/ci.yml` 存在，push/PR 触发，YAML 语法有效。

### ACC-P0-003：许可证与约束文档齐全
`LICENSE`、`CONTRIBUTING.md`、`SECURITY.md`、`CODE_OF_CONDUCT.md`、`AGENTS.md` 均存在且非空。

### ACC-P0-004：依赖清单合规
`go.mod` 直接依赖仅 `golang.org/x/net` 与 `golang.org/x/sys`（`go list -m all` 检查通过）。

## P1 探针

### ACC-P1-001：HTTP echo 会话拉回
本地起探针后，携带会话 UUID 的 HTTP 请求可在 `GET /api/session/{id}` 拉回完整请求头观测。

### ACC-P1-002：TCP_INFO 观测可达
同一会话的 TCP 对端指纹（MSS/WScale/SACK/TS/ECN/RTT）可经会话接口拉回。

### ACC-P1-003：UDP/NAT 回包
UDP echo 从同端口回包；NAT 探测从异端口回包，异 IP 路径在 `-second-ip` 启用时可用。

### ACC-P1-004：JA3/JA4 固定向量
构造的 ClientHello（含跨 TCP 分片用例）解析出预期 JA3/JA4；单元测试全绿。

### ACC-P1-005：端口自发现
`GET /api/info` 返回全部监听端口与探测种类，与实际监听一致。

### ACC-P1-006：会话 TTL 清理
会话过期后 `GET /api/session/{id}` 返回 404，注册表不增长。

### ACC-P1-007：会话不可枚举
未知/过期会话 ID 一律 404，不泄露存在性。

## P2 客户端

### ACC-P2-001：本地采集一致
接口/路由/MTU/DNS 采集结果与系统命令（`ip`/`resolvectl`）输出一致。

### ACC-P2-002：NAT 判定结构
NAT 判定输出原始事实序列 + 判定标签 + 前提说明。

### ACC-P2-003：PMTU 探测一致
PMTU 探测在受控路径（本地回环/已知 MTU 路径）结果一致，无虚假黑洞结论。

### ACC-P2-004：DNS 不误报
无劫持环境对比结果一致不误报；fake-ip 环境标注"DNS 被代理接管"而非"DNS 劫持"。

### ACC-P2-005：TUN 归因与双栏
TUN 环境正确识别并归因；`--direct` 在存在物理直连路径时输出双栏对比，路由守卫失败时明确提示。

### ACC-P2-006：端口连通性一致
可达/不可达端口检测结果与探针回报一致，无误判。

### ACC-P2-007：信誉查询降级
IP 信誉查询返回 ASN/ISP/机房字段；`IPINFO_TOKEN` 缺失时降级不崩溃。

### ACC-P2-008：UDP 归因
TUN 环境下 TCP 通 UDP 不通时输出"代理不转发 UDP"归因，而非"端口封锁"。

### ACC-P2-009：无 root 基础测量
基础测量在无 root 下完成；需特权操作显式声明。

## P3 报告

### ACC-P3-001：诚实上下文与三层视角
文本报告概览区含固定诚实上下文行，按出口/中间层/终点三层视角组织，路径归因标注完整。

### ACC-P3-002：JSON 一致性
`--json` 输出字段与文本报告一致，可机器消费。

### ACC-P3-003：事实先于判定
报告对每项判定先列原始事实再给标签与置信度。

## P4 端到端

### ACC-P4-001：本地 e2e 通过
本地起探针跑全流程（HTTP/TCP/UDP/TLS/NAT/PMTU/DNS/信誉）脚本通过并断言关键字段。

### ACC-P4-002：VPS 冒烟通过
真实 VPS 冒烟：默认端口、`/api/info` 自发现、会话拉取、TCP_INFO 与 TLS 嗅探可用；记录写入 `validation/`。

### ACC-P4-003：耗时边界
全流程单次测量 ≤30s；探针不可达时 ≤60s 明确失败。

## P5 加固与发布

### ACC-P5-001：畸形载荷不崩溃
畸形/超长载荷与并发连接下探针不崩溃、不执行载荷。

### ACC-P5-002：v0.1.0 发布门禁
构建矩阵全绿、变更日志完整、签名 `v0.1.0` tag 与发布提升 PR 版本一致。

### ACC-P5-003：探针零落盘
探针在运行目录/临时目录无任何数据落盘（只读/tmpfs 冒烟）。

### ACC-P5-004：最小监听面
探针仅监听声明的端口；未启用能力无额外监听。
