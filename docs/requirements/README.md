---
status: Accepted
owners: NetSee maintainers
last_reviewed: 2026-08-16
applies_to: netsee requirement baseline
references:
  - ../product/vision.md
  - ../product/scope.md
  - ../roadmap.md
---

# NetSee — 网络暴露面检测工具（需求与方案基线）

> 状态：方案已冻结，待实施（Accepted；功能需求与验收项分别见 `functional.md`、`acceptance.md`）
> 日期：2026-08-16

## 1. 项目定位

一句话：**暴露面对比测量仪**——检测"我的流量在网络上被沿途节点能看到什么"，并以对比形式呈现（直连 / 代理出口 / 经中间层）。

不是"我在对方眼里什么样"的算命器：99.9% 的服务器不关心你是谁，工具测的是**能力边界**（沿途节点*能*看到什么），不是**实际威胁**（谁真的在看）。报告必须内置这一诚实上下文，防止虚假暴露感与虚假安全感。

工具形态：观测点模拟器。客户端本地采集 + 自建探针（VPS）作为远端观测点回报"对方视角"事实。

## 2. 核心决策记录

| 决策点 | 结论 | 理由 |
|---|---|---|
| 部署形态 | 客户端 + 自建探针（VPS） | 探针是权威远端视角，可测对称 NAT、UDP 映射、端口封锁 |
| 技术栈 | Go，依赖仅 `x/net` + `x/sys`，其余标准库 | 单二进制、跨平台、网络生态成熟 |
| 输出 | CLI 彩色文本报告 + `--json` | 轻量、可机器消费 |
| 中间层 | 不专门做（v2 可选 CONNECT 模式） | 终点 echo 已覆盖中间层 95%+ 观测能力（终点 ⊇ 中间层）；自建中间层引入转发正确性、TLS 终止、证书信任的沉重负担 |
| 仓储 | 独立仓库 `~/Projects/powercess/netsee/`（private，推 GitHub org `powercess`） | 与浮点相关项目零依赖、技术栈不同；org 已有 floatile/infra 平级独立仓库模式 |
| 核心价值 | **对比**（直连 vs 代理出口、开/关代理），非单次绝对值 | 指纹与 NAT 行为保质期短、随软件更新变化 |

## 3. 目标 / 非目标

### 目标
- 回答"我的流量途经的每个节点（出口 NAT / 路径中间层 / 目标终点）各能看到我多少信息"
- 代理/VPN 效果验证：出口 IP 归属、机房识别、UDP 连通、DNS 泄露、指纹是否被改写
- 网络排障：端口封锁、PMTU 黑洞、IPv6 可达性、DNS 劫持
- 隐私暴露面自查：TCP/TLS 指纹、SNI 明文、明文 DNS
- TUN 代理场景下正确归因（测到的是代理出口，不是本机直连）

### 非目标
- 不做实时抓包/pcap 分析（本地不抓自己流量，全部经探针回报）
- 不做浏览器 WebRTC/canvas 指纹（那是浏览器视角，CLI 测不了）
- 不做常驻长期监测 daemon（定期测量 + 变化告警是另一种产品形态，另行确认）
- 不做被动中间层/tap 网关（无增量，运维负担重）

## 4. 架构

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

- 探针只记录事实；客户端做本地采集 + 汇总判定
- 判定结论标注置信度与前提（如"单 IP 无法区分对称/端口受限映射"）

### 目录结构

```
netsee/
├── cmd/probe/          探针服务器 (VPS 上跑)
├── cmd/netsee/         客户端 CLI
├── internal/proto/     共享类型: Obs(观察记录), Store(会话注册表), Info(端口自发现)
├── internal/probe/
│   ├── ja3.go          ClientHello 解析 → JA3/JA4
│   ├── tls.go          嗅探监听器(握手前抓 ClientHello)
│   ├── tcpinfo.go      TCP_INFO → 对端指纹(MSS/WS/SACK/TS/ECN/RTT)
│   └── server.go       HTTP/TCP/UDP 监听编排
├── internal/client/
│   ├── session.go      探针客户端 + 端口发现
│   ├── local.go        接口/路由/MTU/resolv.conf
│   ├── nat.go          NAT 类型测试
│   ├── pmtu.go         路径 MTU (Linux DF 位)
│   ├── dns.go          DNS 劫持检测 (系统解析器 vs DoH)
│   └── reputation.go   ip-api/ipinfo 信誉查询
└── internal/report/    报告结构 + 文本/JSON 渲染
```

## 5. 检测矩阵

| 层 | 检测项 | 方法 | 数据源 |
|---|---|---|---|
| 网络 | 公网 IP v4/v6、出口数 | 探针观察 src IP 去重 | 探针 |
| 网络 | ASN/ISP/机房/代理 | ip-api + 可选 IPINFO_TOKEN | 外部 |
| NAT | 类型分类 | 多 socket 映射稳定性 + 端口/IP 过滤测试 | 探针 UDP |
| NAT | 对称映射 | 同 socket 发往不同目标端口，源端口是否变化 | 探针 |
| TCP | 对端指纹 | 探针 TCP_INFO：MSS/WScale/SACK/TS/ECN + RTT | 探针 |
| TLS | JA3/JA4 指纹 | 探针嗅探 ClientHello 并解析 | 探针 |
| HTTP | 对方看到的请求头 | echo 回报完整 header | 探针 |
| 出站 | 端口连通性 | 客户端尝试 + 探针回报比对（防误判） | 双方 |
| 路径 | MTU / PMTU 黑洞 | Linux `IP_PMTUDISC_DO` 递增载荷 | 双方 |
| DNS | 劫持/分流 | 系统解析器 vs dns.google DoH 对比 | 本地+外部 |
| 策略 | 透明代理痕迹 | HTTP obs 中 XFF/Via/注入头 | 探针 |

## 6. 探针协议

- **会话**：客户端生成 UUID，随每次连接携带（HTTP 走 `X-Netsee-Session` header，TCP/UDP 走首条 JSON 载荷，TLS 走 SNI 前缀 `<session>.n`）
- **UDP 载荷**：`{"session","kind"}`，kind ∈ `echo|nat|reach|pmtu`；探针一律从同端口回包（NAT 测试额外从不同端口/不同 IP 回）
- **`GET /api/session/{id}`**：客户端拉取该会话全部观察记录（对方视角总表）
- **`GET /api/info`**：端口自发现（HTTP/TLS/UDP/NAT/额外端口/第二 IP），客户端零配置
- 会话注册表内存实现，TTL 清理

canonical 字段与兼容性规则见 `docs/protocol/probe.md`。

## 7. NAT 判定规则与边界（诚实标注）

- 单 IP 探针：能区分 直连 / 端口受限锥形 / 锥形(端口不过滤) / 对称式映射，但**全锥 vs 受限锥、对称 vs 端口依赖映射**需第二 IP
- 探针配 `-second-ip` 后：完整 RFC 5780 分类
- 报告始终先列原始事实（观测到的 src ip:port 序列），再给判定标签

## 8. TUN 代理场景处理（路径归因层）

**核心结论：TUN 模式下远端观测反映的是代理出口，不是本机环境。** 必须识别并明确归因，否则系统性误导。

### 对检测维度的影响

| 检测项 | TUN 模式行为 | 误判风险 |
|---|---|---|
| 公网 IP | 探针看到代理出口 IP | 当作本机 NAT 出口 |
| NAT 类型 | 测的是代理出口 NAT 行为 | 归因错误 |
| TCP 指纹 | 代理进程的 TCP 栈（clash Go 栈 / sing-box 栈） | 推断错误 OS |
| TLS 指纹 | uTLS 模拟浏览器指纹 或 代理原生栈 | 归因错误 |
| UDP | 多数 TUN 代理不转发 UDP | 误报 ISP 封 UDP |
| DNS | fake-ip 模式返回 `198.18.x.x` | 误报 DNS 劫持 |
| PMTU | 代理内路径 MTU | 误报路径 MTU |

### 路径归因层（v1 必需，属正确性要求）
1. **TUN 识别**：默认路由出口接口名（`tun*`/`utun*`/`wg*`）→ 标记"流量经 TUN 接管"
2. **fake-ip 识别**：resolv.conf 指向 `198.18.0.0/15` 或解析返回该段 → 抑制 DNS 劫持误报，改提示"DNS 被代理接管"
3. **代理程序指纹推断**：探针观测与已知代理栈特征比对（Go 运行时栈 + 特定 TLS 指纹 ≈ clash 等）
4. **UDP 归因**：TCP 通但 UDP 不通时，先排除"TUN 不转发 UDP"再下"端口封锁"结论

### `--direct` 对比模式
本机存在物理直连路径时（探针 IP 加直连路由绕过 TUN），输出双栏对比：

```
              直连出口          代理出口
公网 IP       203.0.113.7      45.77.x.x (新加坡)
TCP 指纹      Linux 系统栈      Go 运行时栈
TLS JA3      xxx               yyy (uTLS Chrome)
NAT 类型      端口受限锥形       全锥(代理出口)
```

需 root 插路由表，部分 TUN 程序覆盖路由守卫 → 尽力而为，失败明确提示。**对比是核心价值，进 v1。**

## 9. 报告形态

- 文本报告：三层视角（出口 / 路径中间层 / 终点）组织，每项标注观测点
- 概览区固定一行诚实上下文："沿途节点有*能力*看到以下信息；是否真的在看取决于具体服务商。本工具测的是暴露面，不是实际被监视。"
- `--json`：完整结构化输出
- 报告结构：概览（公网 IP v4/v6、出口数、NAT 类型、RTT、突出发现）→ 本机网络 → 对方视角总表 → TCP 指纹 → TLS 指纹 → HTTP 视角 → 端口连通性 → 路径 MTU → DNS → IP 信誉

## 10. 版本范围

### v1
- 终点 echo 探针（HTTP/TCP/UDP/TLS）+ 客户端 CLI
- 路径归因层（TUN/fake-ip 识别 + 报告标注 + 误报抑制）
- 双栏对比（直连 vs 代理出口，`--direct` 尽力而为）
- 报告诚实上下文

### v2（可选，不承诺）
- 中间层 CONNECT 模式（探针加代理端口，客户端 `-via` 开关，输出"直连 vs 穿透"对比）——百来行，复用 `proto.Obs`
- `--direct` 完整化
- 常驻监测形态（单独确认）

## 11. 里程碑

1. proto + 探针（HTTP echo / TCP_INFO / UDP + NAT 回包 / TLS 嗅探 + JA3/JA4）
2. 客户端（本地采集 / 端口发现 / NAT 测试 / PMTU / DNS / 信誉）
3. 报告渲染（文本 + JSON，含诚实上下文与路径标注）
4. 端到端测试（本地起探针跑全流程）+ 真实 VPS 冒烟
5. 单元测试：JA3 解析固定答案、ClientHello 跨分片

阶段化实施计划、验收项与出口条件见 `docs/roadmap.md`。

## 12. 仓储与目录

- 独立仓库：`~/Projects/powercess/netsee/`（2026-08-16 已 `git init`，private，推 GitHub org `powercess`）
- 本文件为需求基线，随实施在 `docs/requirements/` 内演进为稳定 ID 需求集（见 `functional.md`、`non-functional.md`）

## 13. 环境要求

- 开发机：Linux（当前无 Go，需安装：`pacman -S go` / `apt install golang` / 官方 tarball）
- 探针 VPS：Linux，公网 IPv4（可选 IPv6、第二 IP 做完整 NAT 分类）
- 探针默认端口 `8080/8443/8444/8445` + 可配额外端口（测封锁，如 53/123/500/4500）
- `<1024` 端口需 root 或 `CAP_NET_BIND_SERVICE`；TCP_INFO 与 UDP TTL 不需要 root
- 内存自签 TLS 证书（探针只做指纹嗅探，不承担正式 PKI）

## 14. 风险与已知边界

- 指纹数据保质期短（JA3 因 uTLS/浏览器更新可靠性下降）→ 对比优先于绝对值
- 单 IP 探针的 NAT 分类不完整 → 报告显式标注前提
- TUN 场景的归因依赖代理程序指纹比对，可能不匹配未知代理 → 未匹配时只标"代理出口"不点名
- 部分 ISP 对探针端口做入站过滤 → 端口测试结果需结合探针回报解读
