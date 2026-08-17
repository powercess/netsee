# NetSee v0.1.0

网络暴露面检测工具首个版本：客户端本地采集 + 自建探针（VPS）远端观测点。
测的是**暴露面**（沿途节点*能*看到什么），不是实际被监视。

## 新增（摘要）

- **探针** `cmd/probe`：HTTP echo + TCP_INFO、TLS 嗅探 JA3/JA4（官方固定向量 + 跨分片）、UDP echo/NAT 回包、会话注册表（内存 + TTL）、端口自发现、观测拉回
- **客户端** `cmd/netsee`：本地采集、NAT 类型/对称映射测试、PMTU、DNS 系统 vs DoH、IP 信誉、TUN/fake-ip/代理栈归因、`--direct` 直连对比
- **报告** `internal/report`：三层视角 + 观测点标注、诚实上下文固定行、事实先于判定、文本/JSON 同构
- **治理**：MIT 许可、文档约束、CI（含 6 组合跨平台构建矩阵）、端到端与 VPS 冒烟脚本

完整变更见 [CHANGELOG.md](CHANGELOG.md)。

## 兼容性

- 探针协议版本 1（`/api/info.protocol_version`）
- 探针默认端口 8080（HTTP）/ 8443（TLS 嗅探）/ 8444（UDP）/ 8445（NAT）
- 协议兼容规则见 `docs/protocol/probe.md`

## SBOM（依赖）

- `golang.org/x/sys v0.47.0` —— 唯一直接依赖
- 其余全部标准库；无 CGO（静态链接，单二进制）
- 完整清单：`go list -m all`

## 构建与验证

- 构建矩阵：linux/darwin/windows × amd64/arm64（CI 全绿）
- 测试：`go test ./...`、`-race`、fuzz（ClientHello ≈1900 万 execs，修复 2 处越界 panic）、`scripts/e2e-local.sh`、`scripts/vps-smoke.sh`
- 探针静态编译部署（`CGO_ENABLED=0`）：Linux amd64/arm64、darwin amd64/arm64、windows amd64/arm64

## 未验证平台/场景

- 运行时实测仅 **Linux**；darwin/windows 编译通过但未运行
- `second-ip` 异 IP 回包路径（完整 RFC 5780 分类）需第二公网 IP
- `--direct` 真实直连对比需 TUN 代理环境
- 探针端口公网开放（无鉴权；按设计零落盘、会话内存 TTL）；生产部署建议防火墙收口（`docs/operations/probe.md`）
