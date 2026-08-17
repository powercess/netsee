# NetSee

网络暴露面检测工具——**暴露面对比测量仪**：检测"我的流量在网络上被沿途节点能看到什么"，并以对比形式呈现（直连 / 代理出口 / 经中间层）。

不是"我在对方眼里什么样"的算命器：工具测的是**能力边界**（沿途节点*能*看到什么），不是**实际威胁**（谁真的在看）。报告内置诚实上下文，防止虚假暴露感与虚假安全感。

形态：客户端本地采集 + 自建探针（VPS）作为远端观测点，回报"对方视角"事实。

## 当前状态

项目处于 **P0：治理基线** 阶段。仓库已建立完整文档约束（分支/Commit/PR/发布规则、威胁模型、需求与验收稳定 ID、文档门禁），并已推送私有远端 `powercess/netsee`。Go 代码尚未开始（P1 探针）。参见[演进路线](docs/roadmap.md)。

## 核心原则

- **对比优先于绝对值**：指纹与 NAT 行为保质期短、随软件更新变化；核心价值是直连 vs 代理出口的差异。
- **诚实上下文**：报告区分暴露面与实际监视；原始事实先于判定标签；标注前提与置信度。
- **路径归因**：TUN 模式下远端观测反映代理出口而非本机环境，必须识别并明确归因，否则系统性误导。
- **依赖纪律**：单二进制、跨平台；依赖仅 `x/net` + `x/sys`，其余标准库。

## 文档入口

- [文档治理与事实源](docs/README.md)
- [演进路线与实施方案](docs/roadmap.md)
- [产品定位](docs/product/vision.md) / [范围与非目标](docs/product/scope.md)
- [需求基线](docs/requirements/README.md) / [功能需求](docs/requirements/functional.md) / [验收项](docs/requirements/acceptance.md)
- [总体架构](docs/architecture/overview.md) / [探针协议](docs/protocol/probe.md)
- [威胁模型](docs/security/threat-model.md) / [探针运维](docs/operations/probe.md)
- [贡献与提交规范](CONTRIBUTING.md) / [Agent 仓库指令](AGENTS.md)

## 计划中的首个垂直切片

```text
本机发起测量（带会话 UUID）
  -> 探针按协议观测（HTTP/TCP/UDP/TLS）
  -> 客户端拉取对方视角总表（/api/session/{id}）
  -> 叠加本地采集（接口/路由/NAT/PMTU/DNS）
  -> TUN/代理路径归因
  -> 输出对比报告（文本/JSON，含诚实上下文）
```

该闭环完成前，不把中间层 CONNECT、常驻监测等 v2 项作为实现目标。
