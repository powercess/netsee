# NetSee repository instructions

本文件作用于整个仓库。目标是让人工开发者和 Agent 在信息不完整时仍能找到唯一事实源，保证测量正确性、诚实报告和安全边界。

## 开始任务

1. 阅读 `CONTRIBUTING.md` 和 `docs/README.md`。
2. 从 `docs/requirements/` 找到稳定需求 ID 和验收项；从 `docs/roadmap.md` 确认阶段归属。
3. 按任务类型阅读对应事实源和 Accepted ADR。
4. 检查 `git status`、当前分支和相关 diff，保留不属于当前任务的修改。
5. 没有需求、验收边界或必要决策时，先补文档或停止并报告。

## 事实源路由

| 任务 | 事实源 |
|---|---|
| 普通功能、修复和重构 | `docs/requirements/`、`docs/architecture/overview.md` |
| 探针行为、监听、会话 | `docs/protocol/probe.md`、`docs/security/threat-model.md` |
| 检测维度、判定规则 | `docs/requirements/functional.md`、`docs/roadmap.md` |
| 报告与诚实上下文 | `docs/product/scope.md`、`docs/roadmap.md` P3 |
| 威胁、信任边界、探针部署 | `docs/security/threat-model.md`、`docs/operations/probe.md` |

文档是事实源，不是流程装饰；与正式文档冲突时必须停止并消除冲突。

## 不可破坏的边界

- 探针不得执行、解释或持久化客户端载荷；echo 只回显原始字节或固定字段。
- 探针会话注册表只存内存并 TTL 清理，不得写磁盘；不得在日志中持久化完整请求头、会话载荷或高基数源数据。
- TLS 嗅探只读取握手前 ClientHello（JA3/JA4 所需字段），不得解密或记录后续流量。
- 协议以 `docs/protocol/probe.md` 为准；客户端与探针不得各自维护相互漂移的类型。
- 报告必须区分"暴露面/能力"与"实际监视"；NAT 等判定必须附原始事实序列、前提与置信度。
- TUN/fake-ip 归因缺失时不得把代理出口误报为本机直连；UDP 不通先排除"TUN 不转发 UDP"再下"端口封锁"结论。
- 不得把设计目标写成已验证结论；没有环境和证据时写 `Unverified`。
- 不得删除、忽略或弱化失败测试来通过门禁。

## Git 授权与协作

- Agent 未经用户明确授权不得创建或切换分支、暂存、提交、push、rebase、merge、打 tag 或改写历史。
- 每次 Git 修改操作前重新检查工作区、分支、暂存区和相关 diff，不假设共享工作区状态未改变。
- 获准暂存时只按路径暂存本任务文件，不得使用 `git add .`、`git add -A` 等宽泛命令。
- 保留并避让用户或其他协作者的修改，不得覆盖、回滚或夹带进入当前变更。
- 禁止破坏性 Git 操作和对共享历史 force-push；具体规则以 `CONTRIBUTING.md` 为准。

## 变更联动

- 改需求：同步验收项和受影响设计。
- 改检测维度或判定规则：同步检测矩阵、报告形态与相关测试向量。
- 改协议：同步 `docs/protocol/probe.md`、两端实现、兼容测试；破坏性变更新增 ADR。
- 改信任边界、监听端口或数据保留：同步威胁模型、运维文档与拒绝路径测试。
- 改 TUN/归因逻辑：同步误报抑制用例与报告标注规则。
- 改依赖或构建：同步技术栈与供应链影响。

## 代码与验证

- 遵循 `docs/development/coding-standards.md` 和 `docs/development/testing.md`。
- 当前 Phase 0 至少运行 `bash scripts/check-docs.sh`。
- Go 代码落地后，默认门禁必须包含 `gofmt`、`go vet`、`go test` 和文档校验（CI 已配置，见 `.github/workflows/ci.yml`）。
- 性能结论必须来自 release 构建，并记录硬件、内核、网络路径和原始数据。

## 完成定义

变更必须目标单一、可审查、可回退；实现和失败路径完整；相关测试通过；事实源、ADR、安全、协议和运维文档按联动规则更新；交付说明列出实际命令、结果和未验证项。
