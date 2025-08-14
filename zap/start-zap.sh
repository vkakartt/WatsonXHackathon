#!/bin/sh

PORT=${PORT:-1000}
API_KEY=${ZAP_API_KEY:-aaef54aee7ea6b3df86e50f888a8d2c7}

echo "Starting OWASP ZAP on port $PORT"

zap.sh -daemon \
  -host 0.0.0.0 \
  -port "$PORT" \
  -config api.key="$API_KEY" \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config api.disablekey=false \
  -config network.proxy.chain.enabled=false \
  -config network.connection.proxyChain.skipName=.* \
  -config connection.dnsTtlSuccessfulQueries=-1