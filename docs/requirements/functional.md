---
status: Accepted
owners: NetSee maintainers
last_reviewed: 2026-08-16
applies_to: functional requirements
references:
  - README.md
  - acceptance.md
---

# NetSee 功能需求

需求来自 `README.md`（方案基线）的检测矩阵、探针协议、TUN 归因与报告形态。每条功能需求必须有关联验收项。

## 探针（观测点）

### FR-PROBE-001：HTTP echo 回报完整请求头
状态：Implemented
验收：ACC-P1-001

### FR-PROBE-002：TCP 对端指纹（TCP_INFO）
状态：Implemented
验收：ACC-P1-002
探针经 TCP_INFO 采集对端 MSS/WScale/SACK/TS/ECN/RTT，形成对端指纹。

### FR-PROBE-003：UDP echo 同端口回包
状态：Implemented
验收：ACC-P1-003
探针一律从收到载荷的同端口回包。

### FR-PROBE-004：NAT 探测回包（异端口/异 IP）
状态：Implemented
验收：ACC-P1-003
NAT 测试额外从不同端口、不同 IP（`-second-ip`）回包；未配置第二 IP 时异 IP 回包路径必须存在且返回明确不可用。

### FR-PROBE-005：TLS 嗅探 ClientHello → JA3/JA4
状态：Implemented
验收：ACC-P1-004
握手前嗅探 ClientHello，跨 TCP 分片累积解析，输出 JA3/JA4 指纹；不得解密或记录后续流量。

### FR-PROBE-006：会话注册表（内存 + TTL）
状态：Implemented
验收：ACC-P1-006
会话 UUID 关联全部观测记录；注册表仅存内存，TTL 到期清理，不写磁盘。

### FR-PROBE-007：端口自发现（GET /api/info）
状态：Implemented
验收：ACC-P1-005
返回 HTTP/TLS/UDP/NAT 监听端口、额外端口与第二 IP 状态，客户端零配置。

### FR-PROBE-008：会话观测拉取（GET /api/session/{id}）
状态：Implemented
验收：ACC-P1-001
客户端按会话拉取全部观测记录（对方视角总表）。

### FR-PROBE-009：会话标识传递
状态：Implemented
验收：ACC-P1-001
HTTP 走 `X-Netsee-Session` header，TCP/UDP 走首条 JSON 载荷，TLS 走 SNI 前缀 `<session>.n`。

## 客户端（本地采集与判定）

### FR-CLIENT-001：本地接口/路由/MTU/DNS 采集
状态：Implemented
验收：ACC-P2-001
采集默认路由、出口接口、MTU、resolv.conf 解析器配置。

### FR-CLIENT-002：NAT 类型测试
状态：Implemented
验收：ACC-P2-002
多 socket 映射稳定性 + 端口/IP 过滤测试，输出原始事实序列与判定标签。

### FR-CLIENT-003：对称映射检测
状态：Implemented
验收：ACC-P2-002
同 socket 发往不同目标端口，观测源端口是否变化。

### FR-CLIENT-004：出站端口连通性
状态：Implemented
验收：ACC-P2-006
客户端尝试 + 探针回报比对，防误判。

### FR-CLIENT-005：PMTU 探测
状态：Implemented
验收：ACC-P2-003
Linux `IP_PMTUDISC_DO` 递增载荷探测路径 MTU 与 PMTU 黑洞。

### FR-CLIENT-006：DNS 劫持/分流检测
状态：Implemented
验收：ACC-P2-004
系统解析器 vs dns.google DoH 对比解析结果。

### FR-CLIENT-007：IP 信誉查询
状态：Implemented
验收：ACC-P2-007
ip-api 查询 ASN/ISP/机房/代理归属；可选 `IPINFO_TOKEN` 增强；令牌缺失时降级不崩溃。

### FR-CLIENT-008：TUN 识别
状态：Implemented
验收：ACC-P2-005
默认路由出口接口名（`tun*`/`utun*`/`wg*`）→ 标记"流量经 TUN 接管"。

### FR-CLIENT-009：fake-ip 识别与劫持误报抑制
状态：Implemented
验收：ACC-P2-004
resolv.conf 指向 `198.18.0.0/15` 或解析返回该段 → 抑制 DNS 劫持误报，改提示"DNS 被代理接管"。

### FR-CLIENT-010：代理程序指纹推断
状态：Implemented
验收：ACC-P2-005
探针观测与已知代理栈特征比对（Go 运行时栈 + 特定 TLS 指纹 ≈ clash 等）；未匹配时只标"代理出口"不点名。

### FR-CLIENT-011：UDP 归因
状态：Implemented
验收：ACC-P2-008
TCP 通但 UDP 不通时，先排除"TUN 不转发 UDP"再下"端口封锁"结论。

### FR-CLIENT-012：--direct 双栏对比
状态：Implemented
验收：ACC-P2-005
探针 IP 加直连路由绕过 TUN，输出直连 vs 代理出口双栏；需 root，路由守卫覆盖时明确提示失败。

## 报告

### FR-REPORT-001：文本报告三层视角 + 诚实上下文
状态：Accepted
验收：ACC-P3-001
以出口/路径中间层/终点三层视角组织，概览区含固定诚实上下文行，每项标注观测点。

### FR-REPORT-002：--json 完整结构化输出
状态：Accepted
验收：ACC-P3-002
JSON 输出与文本报告字段一致，可机器消费。

### FR-REPORT-003：原始事实先于判定标签
状态：Accepted
验收：ACC-P3-003
先列观测到的原始事实（如 src ip:port 序列），再给判定标签。

### FR-REPORT-004：判定标注置信度与前提
状态：Accepted
验收：ACC-P3-003
NAT 分类等结论标注前提（如"单 IP 无法区分对称/端口受限映射"）。

### FR-REPORT-005：路径归因标注
状态：Accepted
验收：ACC-P3-001
TUN/代理出口场景在报告中明确标注归因。
