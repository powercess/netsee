---
status: Accepted
owners: NetSee maintainers
last_reviewed: 2026-08-16
applies_to: testing strategy
references:
  - coding-standards.md
  - ../requirements/acceptance.md
---

# NetSee 测试策略

## 单元测试

- 表驱动；每个用例声明输入、预期输出与依据。
- JA3/JA4：固定测试向量（真实浏览器 ClientHello 抓包固化），含**跨 TCP 分片**用例（任意分片边界累积解析结果一致）。
- `internal/proto`：序列化/反序列化往返、未知字段容忍（兼容性规则）、畸形输入拒绝。
- NAT 判定：构造观测序列 → 断言标签与前提（不依赖真实公网）。

## 集成测试

- 标记不依赖真实公网的测试默认运行；依赖公网/特权的测试以构建标签或环境变量隔离（如 `-tags integration`、`NETSEE_E2E=1`）。
- e2e：本地起探针跑全流程（HTTP/TCP/UDP/TLS/NAT/PMTU/DNS/信誉），断言报告关键字段（ACC-P4-001）。

## 冒烟与验证

- VPS 冒烟清单写入 `docs/validation/`：环境、命令、原始数据位置、限制、有效期。
- 畸形载荷 fuzz 冒烟：随机/超长 JSON、超大 UDP、并发洪泛下探针不崩溃（ACC-P5-001）。
- 性能结论来自 release 构建，记录硬件、内核、网络路径。

## 纪律

- 不得删除、忽略或弱化失败测试来通过门禁。
- 测试必须能独立复现失败原因；不测试实现细节。
- CI 门禁：`gofmt`（无 diff）、`go vet`、`go test ./...`、`bash scripts/check-docs.sh`。
