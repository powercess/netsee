# NetSee

**网络暴露面检测工具**：回答一个简单的问题——「我的网络流量走出去，沿途节点到底能看到我多少信息？」

它由两部分组成：**客户端**（跑在你本机）+ **自建探针**（跑在一台 VPS 上，作为"远端观测点"）。探针把你流量的"对方视角"事实原样拉回来，和你本机的认知对比，最后生成一份报告。

> 测的是**暴露面**（沿途节点*有能力*看到什么），不是实际威胁（谁真的在看）。沿途节点有能力看到以下信息；是否真的在看取决于具体服务商。本工具测的是暴露面，不是实际被监视。

---

## 它能帮你回答什么

| 你关心的问题 | NetSee 给出的答案 |
|---|---|
| 我的代理/VPN 真的生效了吗？出口 IP 在哪？ | 探针看到的真实出口 IP（v4/v6）+ ASN/ISP/机房信誉 |
| 我的网络是什么 NAT 类型？（影响 P2P / 游戏 / WebRTC / 自建服务） | 分类：直连 / 锥形（端口不过滤）/ 端口受限锥形 / 对称式映射 |
| 我的流量有没有被"看光"？ | SNI 明文、明文 DNS、HTTP 请求头、透明代理注入痕迹（XFF/Via） |
| 我的 TLS 指纹长什么样？会不会被识别成代理？ | JA3 / JA4 指纹 + 已知客户端栈比对（Go/浏览器） |
| 端口连不上，是**被封**还是**我的 NAT 不给回包**？ | 客户端尝试 + 探针回报双向比对，防误判 |
| 我的 DNS 有没有被劫持 / 污染 / 分流？ | 系统解析器 vs DoH（dns.google）对比 + fake-ip 识别 |
| 走代理时测到的是代理出口还是本机直连？ | TUN / fake-ip / 代理栈归因，报告明确标注 |
| 我的链路 MTU 是多少？有没有 PMTU 黑洞？ | 递增载荷探测 + 黑洞检测 |

## 检测清单

| 维度 | 检测项 | 观测点 |
|---|---|---|
| 出口 | 公网 IP（v4/v6）、出口数、IP 信誉（ASN/ISP/机房/代理标记） | 探针 + ip-api/ipinfo |
| NAT | 类型分类、对称映射、端口/IP 过滤测试 | 探针 UDP 回包 |
| TCP | 对端指纹：MSS / WScale / SACK / TS / ECN / RTT | 探针 TCP_INFO |
| TLS | JA3 / JA4 / SNI | 探针嗅探握手前 ClientHello |
| HTTP | 对方看到的完整请求头、透明代理痕迹（XFF/Via） | 探针 echo |
| 路径 | 路径 MTU / PMTU 黑洞 | 客户端 DF 位 + 探针回包 |
| DNS | 系统 vs DoH 对比、劫持/分流、fake-ip | 本地解析器 + dns.google |
| 连通性 | 端口可达性（含额外端口测封锁） | 客户端 + 探针双端确认 |

## 工作原理

```
┌──────────────┐   TCP/UDP/TLS/HTTP    ┌──────────────────┐
│  netsee CLI  │ ◄───────────────────► │  netsee-probe    │
│  (本机)       │     会话协议(JSON)     │  (VPS 远端观测点)  │
└──────────────┘                       └──────────────────┘
   │ 本地采集                                  │ 记录"对方视角"事实:
   │ 接口/路由/MTU/DNS                         │  src ip:port, TTL
   │ NAT/PMTU 测试                             │  TCP 选项, JA3/JA4
   │ DNS vs DoH 对比                           │  HTTP 请求头, NAT 行为
   └─ ip-api/ipinfo (IP 信誉)
```

- 每次测量生成一个会话 UUID，探针把该会话的所有观测记录收集起来，客户端按会话拉回。
- 探针**只记录事实、零落盘**（会话内存 + TTL），不执行任何客户端载荷。
- 判定结论始终带**原始事实 + 标签 + 前提 + 置信度**（比如"单 IP 探针无法区分全锥 vs 受限锥"）。

## 快速开始

### 1. 部署探针（一台公网 VPS）

```bash
# 本机构建静态二进制（无 glibc 依赖，任何 Linux 可跑）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o netsee-probe ./cmd/probe
# 上传 VPS 后启动（systemd 示例见 docs/operations/probe.md）
./netsee-probe    # 默认监听 8080(HTTP) 8443(TLS嗅探) 8444(UDP) 8445(NAT)
```

### 2. 跑客户端

```bash
go build -o netsee ./cmd/netsee
./netsee -probe http://你的VPS:8080
```

### 3. 看报告

```
NetSee 网络暴露面检测报告
诚实上下文: 沿途节点有能力看到以下信息；……

一、概览
  公网出口 IP: 39.130.64.75        出口数: 1
  NAT 类型: 对称式映射              探针侧 RTT: 49.09 ms
  突出发现: 对称式 NAT 映射
二、本机网络
  默认路由: ens33 (MTU 1500) 网关 192.168.182.2   DNS 解析器: 192.168.182.2
三、出口层 — NAT 判定
  原始事实: echo→udp端口 src=39.130.64.75:56525 收到=true / echo→nat端口 src=…:56525 …
  判定: 对称式映射（置信度 中）     前提: 单 IP 探针无法区分……
四、对方视角总表（探针观测 9 条） …
五、终点层 — TCP 指纹   mss=1448 wscale=true sack=true ts=true rtt=49.09ms
六、终点层 — TLS 指纹   ja3=… ja4=… sni=…
八、端口连通性  :8080/tcp 通（探针确认）…
九、路径层 — 路径 MTU  1500
十、路径层 — DNS  判定: 一致（未检测到劫持）
十一、出口层 — IP 信誉  China Mobile GD Guangzhou AS9808
```

输出也支持 `-json`，字段与文本报告完全一致，可直接机器消费。

### 常用参数

| 参数 | 说明 |
|---|---|
| `-probe <url>` | 探针地址（默认 `http://127.0.0.1:8080`） |
| `-doh <url>` | DoH 端点（默认 dns.google；`-doh ""` 跳过 DNS 对比） |
| `-direct` | 同时测直连路径 vs 代理出口（需 root，绕过 TUN） |
| `-ipinfo-token` | 可选 ipinfo.io token，增强 IP 信誉 |
| `-json` | 输出完整 JSON 报告 |
| `-version` | 打印版本 |

## 典型场景

- **代理/VPN 效果验证**：开/关代理各跑一次，对比出口 IP、TLS 指纹、DNS 是否改写、UDP 是否转发。
- **隐私暴露面自查**：看 SNI 明文、明文 DNS、HTTP 头是否泄露、NAT 是否对称。
- **网络排障**：端口封锁、PMTU 黑洞、IPv6 可达性、DNS 劫持。
- **TUN 代理归因**：走 clash/sing-box 时，明确"测到的是代理出口，不是本机直连"。

## 它不做什么（诚实边界）

- 不抓包 / 不做 pcap 分析（本地不抓自己流量，全部经探针回报）。
- 不测浏览器指纹（WebRTC / canvas 是浏览器视角，CLI 测不了）。
- 不做常驻监测 / 变化告警（那是另一种产品形态）。
- 不判"谁真的在看"——只测"谁*能*看到"。

## 项目状态

- 路线图 P0-P5 完成，**v0.1.0 已发布**（见 [CHANGELOG.md](CHANGELOG.md)）。
- 本地端到端 + 真实 VPS 冒烟验证通过（记录见 [docs/validation](docs/validation/README.md)）。
- 技术栈：Go，依赖仅 `golang.org/x/sys`；单静态二进制，跨平台构建（linux/darwin/windows × amd64/arm64）。

## 文档入口

- [演进路线与实施](docs/roadmap.md)
- [需求基线](docs/requirements/README.md)
- [探针协议](docs/protocol/probe.md)
- [威胁模型](docs/security/threat-model.md)
- [探针运维（部署/防火墙/systemd）](docs/operations/probe.md)
- [贡献与提交规范](CONTRIBUTING.md)
