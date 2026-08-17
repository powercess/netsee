#!/usr/bin/env bash
# NetSee VPS 冒烟（ACC-P4-002）——针对已部署探针的检查清单。
# 在能访问探针（公网）的机器上运行；需要 curl 与 jq。
#
# 部署参考（docs/operations/probe.md）：
#   GOOS=linux GOARCH=amd64 go build -o netsee-probe ./cmd/probe
#   上传至 VPS，按 systemd unit 启动（默认 8080/8443/8444/8445）。
#
# 用法: bash scripts/vps-smoke.sh <probe-url> [client-binary]
#   例: bash scripts/vps-smoke.sh http://45.77.1.2:8080
set -euo pipefail

PROBE=${1:?用法: bash scripts/vps-smoke.sh <probe-url> [client-binary]}
CLIENT=${2:-}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -z "$CLIENT" ]; then
  echo "==> 构建客户端"
  go build -o /tmp/netsee ./cmd/netsee
  CLIENT=/tmp/netsee
fi

fail=0
check() { # name <shell-expression>
  if eval "$2" >/dev/null 2>&1; then
    echo "PASS: $1"
  else
    echo "FAIL: $1"
    fail=1
  fi
}

echo "==> 1. 端口自发现 /api/info"
INFO=$(curl -sf --max-time 10 "$PROBE/api/info") || { echo "FAIL: /api/info 不可达"; exit 1; }
check "端口字段齐全" 'echo "$INFO" | jq -e ".http_port > 0 and .tls_port > 0 and .udp_port > 0 and .nat_port > 0"'
echo "$INFO" | jq .
check "协议版本" 'echo "$INFO" | jq -e ".protocol_version | length > 0"'

echo "==> 2. HTTP echo 会话拉回（探针视角）"
SESSION=$(cat /proc/sys/kernel/random/uuid)
curl -sf --max-time 10 -H "X-Netsee-Session: $SESSION" -H "X-Custom: vps-smoke" "$PROBE/echo" >/dev/null
OBS=$(curl -sf --max-time 10 "$PROBE/api/session/$SESSION")
check "HTTP 观测拉回" 'echo "$OBS" | jq -e "map(select(.kind==\"http\")) | length >= 1"'
echo "$OBS" | jq -c '.[0] | {src_ip, dst_port, method: .http.method}'
SRCIP=$(echo "$OBS" | jq -r '.[0].src_ip')
echo "公网源 IP（探针视角）: $SRCIP"

echo "==> 3. 客户端全流程（TCP/TLS/UDP/NAT/PMTU/DNS/信誉 + 报告）"
REPORT=$("$CLIENT" -probe "$PROBE" -timeout 15s)
echo "$REPORT"
check "诚实上下文" 'echo "$REPORT" | grep -q "暴露面"'
check "TCP 指纹" 'echo "$REPORT" | grep -q "mss="'
check "TLS 指纹" 'echo "$REPORT" | grep -q "ja3="'
check "NAT 判定" 'echo "$REPORT" | grep -qE "NAT 判定|NAT:"'
check "端口连通性" 'echo "$REPORT" | grep -q "端口连通性"'
check "路径 MTU" 'echo "$REPORT" | grep -q "路径 MTU"'
check "DNS 判定" 'echo "$REPORT" | grep -qE "DNS"'
check "IP 信誉" 'echo "$REPORT" | grep -q "IP 信誉"'

echo "==> 4. 会话不可枚举抽查"
UNKNOWN=$(cat /proc/sys/kernel/random/uuid)
check "未知会话 404" 'test "$(curl -s -o /dev/null -w "%{http_code}" "$PROBE/api/session/$UNKNOWN")" = "404"'

if [ "$fail" -eq 1 ]; then
  echo "==> VPS 冒烟存在失败"
  exit 1
fi
echo "==> VPS 冒烟通过"
echo "把以上输出连同环境信息（OS/内核/探针公网 IP/日期）记录到 docs/validation/README.md"
