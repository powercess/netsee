---
status: Accepted
owners: NetSee maintainers
last_reviewed: 2026-08-16
applies_to: development standards
references:
  - testing.md
---

# NetSee 编码规范

## Go 代码

- 全部代码 `gofmt` 格式化；`go vet ./...` 无告警。
- 网络操作一律携带 `context` 与超时；禁止无限阻塞读。
- 错误必须处理或显式传播；不吞错误、不 `panic` 处理预期错误（仅不可恢复状态 panic）。
- IP 处理优先 `net/netip`；避免字符串 IP 比较。
- 探针载荷解析使用固定 schema 与长度上限，拒绝畸形输入（见 `../security/threat-model.md`）。
- 暴露面函数（`internal/proto`）必须有单元测试；协议字段增删必须同步 canonical 文档。

## 依赖纪律

- 直接依赖仅 `golang.org/x/net`、`golang.org/x/sys`；新增依赖需 ADR 并同步供应链影响。
- 不引入抓包库、TLS 栈重写、GUI 框架等超出范围的依赖。

## 跨平台

- 平台差异收敛在 `internal/client`（如 `IP_PMTUDISC_DO`、TCP_INFO 仅 Linux 可用时返回明确"不支持"）。
- 构建矩阵：linux/darwin/windows × amd64/arm64；无 `CGO` 依赖（纯 Go）。

## 文档联动

- 任何行为变更同步 `docs/` 事实源（`docs/README.md` 修改规则）。
- 新检测维度同步 `functional.md`（新 FR/ACC ID）与 `roadmap.md`。
- 门禁：`bash scripts/check-docs.sh` 必须通过；Go 门禁见 CI（`gofmt`/`vet`/`test`）。
