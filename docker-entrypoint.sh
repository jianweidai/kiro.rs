#!/bin/sh
set -e

CONFIG_DIR="/app/config"
CONFIG_FILE="${CONFIG_DIR}/config.json"

# 如果 config.json 已存在，直接使用
if [ -f "$CONFIG_FILE" ]; then
    echo "Using existing config file: $CONFIG_FILE"
    exec ./kiro-rs -c "$CONFIG_FILE" --credentials "${CONFIG_DIR}/credentials.json"
fi

# 从环境变量生成 config.json
echo "No config.json found, generating from environment variables..."

# apiKey 是必须的
if [ -z "$KIRO_API_KEY" ]; then
    echo "ERROR: KIRO_API_KEY is required (either set env var or mount config.json)"
    exit 1
fi

mkdir -p "$CONFIG_DIR"

# 构建 JSON 配置
cat > "$CONFIG_FILE" <<EOF
{
  "host": "${KIRO_HOST:-0.0.0.0}",
  "port": ${KIRO_PORT:-8990},
  "apiKey": "${KIRO_API_KEY}",
  "region": "${KIRO_REGION:-us-east-1}"
EOF

# 可选字段
[ -n "$KIRO_AUTH_REGION" ]       && echo ",  \"authRegion\": \"${KIRO_AUTH_REGION}\"" >> "$CONFIG_FILE"
[ -n "$KIRO_API_REGION" ]        && echo ",  \"apiRegion\": \"${KIRO_API_REGION}\"" >> "$CONFIG_FILE"
[ -n "$KIRO_ADMIN_API_KEY" ]     && echo ",  \"adminApiKey\": \"${KIRO_ADMIN_API_KEY}\"" >> "$CONFIG_FILE"
[ -n "$KIRO_PROXY_URL" ]         && echo ",  \"proxyUrl\": \"${KIRO_PROXY_URL}\"" >> "$CONFIG_FILE"
[ -n "$KIRO_PROXY_USERNAME" ]    && echo ",  \"proxyUsername\": \"${KIRO_PROXY_USERNAME}\"" >> "$CONFIG_FILE"
[ -n "$KIRO_PROXY_PASSWORD" ]    && echo ",  \"proxyPassword\": \"${KIRO_PROXY_PASSWORD}\"" >> "$CONFIG_FILE"
[ -n "$KIRO_TLS_BACKEND" ]       && echo ",  \"tlsBackend\": \"${KIRO_TLS_BACKEND}\"" >> "$CONFIG_FILE"
[ -n "$KIRO_MACHINE_ID" ]        && echo ",  \"machineId\": \"${KIRO_MACHINE_ID}\"" >> "$CONFIG_FILE"
[ -n "$KIRO_LOAD_BALANCING" ]    && echo ",  \"loadBalancingMode\": \"${KIRO_LOAD_BALANCING}\"" >> "$CONFIG_FILE"
[ -n "$KIRO_VERSION" ]           && echo ",  \"kiroVersion\": \"${KIRO_VERSION}\"" >> "$CONFIG_FILE"

echo "}" >> "$CONFIG_FILE"

echo "Generated config.json:"
cat "$CONFIG_FILE"

exec ./kiro-rs -c "$CONFIG_FILE" --credentials "${CONFIG_DIR}/credentials.json"
