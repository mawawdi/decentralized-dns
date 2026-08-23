#!/usr/bin/env bash
#
# presentation.sh — 1-click live presentation launcher for Decentralized DNS.
# Starts the chain, deploys & seeds contracts, publishes a verified web resource,
# and starts the resolver. Keeps everything running for your live demo.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS="$ROOT/contracts"
RESOLVER="$ROOT/resolver"
DATA_DIR="$ROOT/.presentation-data"
ALICE_PK="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
RPC_URL="http://127.0.0.1:8545"
REST="http://127.0.0.1:8080"
PUBLISH_PORT=42100

mkdir -p "$DATA_DIR/bin" "$DATA_DIR/seed" "$DATA_DIR/resolver-data"

PIDS=()
cleanup() {
  echo ""
  echo -e "\033[1;33m== Shutting down presentation demo ==\033[0m"
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$DATA_DIR"
  echo "Cleaned up."
}
trap cleanup EXIT INT TERM

step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$1"; }

wait_rpc() {
  for _ in $(seq 1 60); do
    if curl -fsS -X POST "$RPC_URL" -H 'content-type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}' >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "Timed out waiting for Hardhat node." >&2
  exit 1
}

wait_for() {
  for _ in $(seq 1 60); do
    if curl -fsS "$1" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "Timed out waiting for $2 ($1)" >&2
  exit 1
}

# 1. Compile & build
step "1. Building binaries and compiling smart contracts..."
( cd "$RESOLVER" && go build -o "$DATA_DIR/bin/" ./cmd/resolver ./cmd/ddns ./cmd/ddns-lookup ./cmd/ddns-fetch )
export PATH="$DATA_DIR/bin:$PATH"

# 2. Start local chain
step "2. Starting local blockchain (Hardhat)..."
( cd "$CONTRACTS" && npx hardhat node --hostname 127.0.0.1 >"$DATA_DIR/chain.log" 2>&1 ) &
PIDS+=($!)
wait_rpc

# 3. Deploy & seed
step "3. Deploying smart contracts and seeding domain 'example'..."
( cd "$CONTRACTS" && npx hardhat run scripts/deploy.ts --network localhost >/dev/null )
( cd "$CONTRACTS" && npx hardhat run scripts/seed.ts --network localhost >/dev/null )

NAMESPACE="$(node -pe 'require("'"$CONTRACTS"'/deployments/localhost.json").contracts.NamespaceDApp')"
REGISTRY="$(node -pe 'require("'"$CONTRACTS"'/deployments/localhost.json").contracts.RecordSchemaRegistry')"

# 4. Start resolver daemon
step "4. Starting the Decentralized DNS Resolver daemon..."
RPC_URL="$RPC_URL" CONTRACT_ADDRESS="$NAMESPACE" REGISTRY_ADDRESS="$REGISTRY" \
  RESOLVER_KEYSTORE="$DATA_DIR/resolver.key" DATA_DIR="$DATA_DIR/resolver-data" ALLOW_PEER_HINTS=true \
  resolver >"$DATA_DIR/resolver.log" 2>&1 &
PIDS+=($!)
wait_for "$REST/healthz" "resolver"

export DDNS_PRIVATE_KEY="$ALICE_PK"
export DDNS_DEPLOYMENTS="$CONTRACTS/deployments/localhost.json"
export DDNS_RESOLVER="$REST"

# 5. Announce resolver to on-chain registry
ddns announce-resolver --endpoint "$REST" >/dev/null 2>&1 || true

# 6. Publish sample website to BitTorrent & anchor on-chain
step "5. Publishing decentralized website for 'example'..."
cat << 'EOF' > "$DATA_DIR/site.html"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>example.ddns · Verified Site</title>
  <style>
    :root { color-scheme: dark; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0d1117;
      color: #e6edf3;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      margin: 0;
      padding: 20px;
      box-sizing: border-box;
    }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 16px;
      padding: 40px;
      max-width: 620px;
      width: 100%;
      box-shadow: 0 16px 32px rgba(0,0,0,0.4);
    }
    .badge {
      display: inline-block;
      background: rgba(35, 134, 54, 0.2);
      color: #3fb950;
      border: 1px solid rgba(63, 185, 80, 0.4);
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 13px;
      font-weight: 600;
      margin-bottom: 20px;
    }
    h1 { margin: 0 0 10px; font-size: 28px; color: #58a6ff; }
    p { color: #8b949e; line-height: 1.6; font-size: 15px; }
    .specs {
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 8px;
      padding: 16px;
      margin: 24px 0;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 13px;
    }
    .specs div { margin-bottom: 8px; }
    .specs div:last-child { margin-bottom: 0; }
    .k { color: #7ee787; }
    .v { color: #d2a8ff; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">✓ On-Chain Cryptographically Verified</div>
    <h1>Welcome to example.ddns</h1>
    <p>This website was retrieved peer-to-peer over BitTorrent, with its content hash (SHA-256), domain ownership, and cryptographic signatures verified directly against the Ethereum blockchain.</p>
    <div class="specs">
      <div><span class="k">Domain:</span> <span class="v">example</span></div>
      <div><span class="k">Protocol:</span> <span class="v">Decentralized DNS (ddns)</span></div>
      <div><span class="k">Storage:</span> <span class="v">BitTorrent P2P Swarm</span></div>
      <div><span class="k">Integrity:</span> <span class="v">SHA-256 + ECDSA Signature OK</span></div>
    </div>
    <p style="font-size: 13px; margin: 0;">Decentralized DNS & PKI · University Presentation Demo</p>
  </div>
</body>
</html>
EOF

ddns publish-resource example "$DATA_DIR/site.html" --selector "service=HTTP" \
  --bt-port "$PUBLISH_PORT" --data-dir "$DATA_DIR/seed" >"$DATA_DIR/publish.log" 2>&1 &
PIDS+=($!)
sleep 2

# Warm up resolver: fetch and cache the verified site into resolver's storage
curl -fsS "$REST/resource?name=example&selector=service%3DHTTP&peer=127.0.0.1:$PUBLISH_PORT" >/dev/null 2>&1 || true

clear 2>/dev/null || true
echo -e "\033[1;32m========================================================================\033[0m"
echo -e "\033[1;32m  🎉 DECENTRALIZED DNS — LIVE PRESENTATION DEMO IS READY & RUNNING!   \033[0m"
echo -e "\033[1;32m========================================================================\033[0m"
echo ""
echo -e "\033[1;36mOpen these in your browser for the presentation:\033[0m"
echo ""
echo -e "  1. \033[1;33mResolver Admin Dashboard:\033[0m"
echo -e "     \033[4;34mhttp://localhost:8080/admin\033[0m"
echo -e "     (Shows live chain block height, cache hits/misses, and peer swarm)"
echo ""
echo -e "  2. \033[1;33mDecentralized Website Gateway:\033[0m"
echo -e "     \033[4;34mhttp://localhost:8080/web/example\033[0m"
echo -e "     (Renders the site retrieved from BitTorrent and verified on-chain)"
echo ""
echo -e "  3. \033[1;33mBrowser Extension:\033[0m"
echo -e "     - Click the \033[1mddns icon\033[0m in Chrome toolbar → Resolve \033[1;32mexample\033[0m"
echo -e "     - Or in address bar type: \033[1;32mddns example\033[0m and press Enter"
echo ""
echo -e "\033[1;30mPress Ctrl+C anytime to stop all services.\033[0m"
echo ""

# Block until user presses Ctrl+C
while true; do
  sleep 1
done
