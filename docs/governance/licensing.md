---
status: Accepted
owners: NetSee maintainers
last_reviewed: 2026-08-16
applies_to: licensing governance
references:
  - ../../CONTRIBUTING.md
---

# 许可证治理

## 决策记录

| 决策点 | 结论 | 日期 | 决策人 |
|---|---|---|---|
| 许可证 | MIT | 2026-08-16 | 用户（CN059） |
| 仓库可见性 | private（GitHub org `powercess`） | 2026-08-16 | 用户（CN059） |
| 版权持有者 | CN059 | 2026-08-16 | 用户（CN059） |

## 约束

- 在许可证决策被接受并添加正式 `LICENSE` 前，本仓库内容不得被视为已获得开源分发授权——该决策已完成，`LICENSE` 为 MIT。
- 仓库当前为 private；转为 public 或对外分发前，必须完成：协议与威胁模型评审、发布门禁（`docs/roadmap.md` P5）、移除任何内部信息。
- 外部贡献者引入需签署条款（如 DCO）时，通过 ADR 追加决策；默认不自动生成 `Co-authored-by:` trailer。
- 发布产物必须包含许可证全文与来源声明（`CONTRIBUTING.md` 发布门禁）。
