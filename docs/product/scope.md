---
status: Accepted
owners: NetSee maintainers
last_reviewed: 2026-08-16
applies_to: product scope
references:
  - vision.md
  - ../requirements/README.md
---

# NetSee 范围与非目标

## 目标

- 回答"我的流量途经的每个节点（出口 NAT / 路径中间层 / 目标终点）各能看到我多少信息"
- 代理/VPN 效果验证：出口 IP 归属、机房识别、UDP 连通、DNS 泄露、指纹是否被改写
- 网络排障：端口封锁、PMTU 黑洞、IPv6 可达性、DNS 劫持
- 隐私暴露面自查：TCP/TLS 指纹、SNI 明文、明文 DNS
- TUN 代理场景下正确归因（测到的是代理出口，不是本机直连）

## 非目标

- 不做实时抓包/pcap 分析（本地不抓自己流量，全部经探针回报）
- 不做浏览器 WebRTC/canvas 指纹（那是浏览器视角，CLI 测不了）
- 不做常驻长期监测 daemon（定期测量 + 变化告警是另一种产品形态，另行确认）
- 不做被动中间层/tap 网关（无增量，运维负担重）
