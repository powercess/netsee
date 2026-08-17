#!/usr/bin/env bash
# NetSee 本地端到端验证（ACC-P4-001 / ACC-P4-003）：
#   起本地探针 → 客户端全流程（真实 DoH + 信誉）→ 断言报告关键字段 → 探针不可达快速失败。
# 用法: bash scripts/e2e-local.sh
set -euo pipefail
cd "$(dirname "$0")/.."

HTTP_PORT=${HTTP_PORT:-18080}
TLS_PORT=${TLS_PORT:-18443}
UDP_PORT=${UDP_PORT:-18444}
NAT_PORT=${NAT_PORT:-18445}
BIND=127.0.0.1

echo "==> 构建"
go build -o /tmp/netsee-probe ./cmd/probe
go build -o /tmp/netsee ./cmd/netsee

echo "==> 启动探针 (:${HTTP_PORT})"
/tmp/netsee-probe -bind "$BIND" -http-port "$HTTP_PORT" -tls-port "$TLS_PORT" \
  -udp-port "$UDP_PORT" -nat-port "$NAT_PORT" -ttl 30s &
PROBE_PID=$!
trap 'kill "$PROBE_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 20); do
  curl -sf "http://$BIND:$HTTP_PORT/api/info" >/dev/null 2>&1 && break
  sleep 0.3
done
curl -sf "http://$BIND:$HTTP_PORT/api/info" >/dev/null || { echo "FAIL: 探针未就绪"; exit 1; }

echo "==> 客户端全流程（真实 DoH + 信誉）"
OUT=$(/tmp/netsee -probe "http://$BIND:$HTTP_PORT" -timeout 10s -json)
echo "$OUT" | jq -e . >/dev/null || { echo "FAIL: JSON 输出无效"; exit 1; }

fail=0
check() { # name jq_expr
  if echo "$OUT" | jq -e "$2" >/dev/null 2>&1; then
    echo "PASS: $1"
  else
    echo "FAIL: $1"
    fail=1
  fi
}

check "诚实上下文固定行" '.honest_context | contains("暴露面")'
check "公网出口 IP"       '.overview.public_ips | length >= 1'
check "NAT 判定（回环直连）" '.nat.label | contains("直连")'
check "NAT 原始事实序列"   '.nat.facts | length >= 4'
check "TCP 指纹"          '.tcp.mss > 0'
check "TLS 指纹 JA3"      '.tls.ja3 | length == 32'
check "HTTP 视角"         '.http.method == "GET"'
check "端口连通性一致"     '[.ports[] | select(.consistent == false)] | length == 0'
check "路径 MTU"          '.mtu.path_mtu > 0'
check "DNS 判定"          '.dns.judgment | length > 0'
check "信誉（成功或降级）"  '.reputation.source | length > 0'
check "耗时 ≤ 30s"        '.duration_sec <= 30'

echo "==> 探针不可达快速失败（≤60s 明确报错）"
START=$(date +%s)
if /tmp/netsee -probe "http://$BIND:1" -timeout 15s -json >/dev/null 2>&1; then
  echo "FAIL: 不可达探针未报错"
  fail=1
else
  ELAPSED=$(($(date +%s) - START))
  if [ "$ELAPSED" -le 60 ]; then
    echo "PASS: 不可达探针 ${ELAPSED}s 内明确失败"
  else
    echo "FAIL: 不可达探针耗时 ${ELAPSED}s"
    fail=1
  fi
fi

if [ "$fail" -eq 1 ]; then
  echo "==> 端到端存在失败"
  exit 1
fi
echo "==> 端到端全部通过"
