---
status: Accepted
owners: NetSee maintainers
last_reviewed: 2026-08-16
applies_to: non-functional requirements
references:
  - README.md
  - acceptance.md
---

# NetSee 非功能需求

### NFR-DEP-001：依赖仅 x/net + x/sys
状态：Implemented
验收：ACC-P0-004
直接依赖只允许 `golang.org/x/net` 与 `golang.org/x/sys`，其余全部标准库。

### NFR-BUILD-001：单二进制跨平台
状态：Implemented
验收：ACC-P5-002
客户端与探针各自为单二进制；构建矩阵覆盖 linux/darwin/windows × amd64/arm64。

### NFR-PERF-001：单次测量耗时边界
状态：Implemented
验收：ACC-P4-003
正常路径单次全流程测量 ≤30s；探针不可达等故障路径 ≤60s 内明确失败。

### NFR-SEC-001：探针不持久化客户端数据
状态：Implemented
验收：ACC-P5-003
探针运行期间任何客户端数据不落盘；会话注册表仅内存 + TTL。

### NFR-SEC-002：探针不执行客户端载荷
状态：Implemented
验收：ACC-P5-001
echo 只回显原始字节或固定字段；载荷一律不解释、不执行。

### NFR-SEC-003：会话 ID 不可枚举
状态：Implemented
验收：ACC-P1-007
会话 ID 使用 UUID v4；未知/过期会话返回 404。

### NFR-SEC-004：探针最小监听面
状态：Implemented
验收：ACC-P5-004
探针只监听显式配置的端口（默认 8080/8443/8444/8445）；未启用能力不得额外监听。

### NFR-OBS-001：无 root 基础测量
状态：Implemented
验收：ACC-P2-009
本地采集、NAT 测试、PMTU、TCP_INFO 无需 root；`<1024` 端口与 `--direct` 路由插表需特权时显式声明。

### NFR-DOC-001：文档门禁
状态：Implemented
验收：ACC-P0-001
`scripts/check-docs.sh` 必须通过：frontmatter 完整、相对链接有效、稳定 ID 不重复、需求有验收映射。
