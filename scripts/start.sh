#!/usr/bin/env bash
#
# start.sh — Launches the Decentralized DNS resolver node and services.
# Supports both Localhost (Hardhat) and Ethereum Sepolia Testnet.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACTS="$ROOT/contracts"
RESOLVER="$ROOT/resolver"
DATA_DIR="$ROOT/data"
REST="http://127.0.0.1:8080"
PUBLISH_PORT=42100

# Load .env if present
if [ -f "$CONTRACTS/.env" ]; then
  # shellcheck disable=SC1091
  source "$CONTRACTS/.env" || true
fi
if [ -f "$ROOT/.env" ]; then
  # shellcheck disable=SC1091
  source "$ROOT/.env" || true
fi

NETWORK="local"
for arg in "$@" "${DDNS_NETWORK:-}"; do
  if [[ "$arg" == "--sepolia" || "$arg" == "sepolia" ]]; then
    NETWORK="sepolia"
    break
  fi
done

mkdir -p "$DATA_DIR/bin" "$DATA_DIR/uploads" "$DATA_DIR/resolver"

# Free ports
free_port() {
  local port="$1"
  if command -v lsof >/dev/null 2>&1; then
    { lsof -ti":$port" 2>/dev/null | xargs -r kill -9 2>/dev/null; } || true
  elif command -v netstat >/dev/null 2>&1 && command -v taskkill >/dev/null 2>&1; then
    { netstat -ano 2>/dev/null | grep -i "listening" | grep ":$port " | awk '{print $NF}' | sort -u | while read -r pid; do
        taskkill //PID "$pid" //F >/dev/null 2>&1 || true
      done
    } || true
  fi
}
free_port 8080
free_port 42100
free_port 42069

PIDS=()
cleanup() {
  echo ""
  echo -e "\033[1;33m== Shutting down services ==\033[0m"
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  echo "Stopped."
}
trap cleanup EXIT INT TERM

step() { printf '\n\033[1;36m▶ %s\033[0m\n' "$1"; }

wait_rpc() {
  local url="$1"
  for _ in $(seq 1 60); do
    if curl -fsS -X POST "$url" -H 'content-type: application/json' \
        --data '{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}' >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "Timed out waiting for RPC node ($url)" >&2
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
step "1. Building binaries..."
( cd "$RESOLVER" && go build -buildvcs=false -o "$DATA_DIR/bin/" ./cmd/resolver ./cmd/ddns ./cmd/ddns-lookup ./cmd/ddns-fetch )
export PATH="$DATA_DIR/bin:$PATH"

if [ "$NETWORK" == "sepolia" ]; then
  RPC_URL="${SEPOLIA_RPC_URL:-${RPC_URL:-https://ethereum-sepolia-rpc.publicnode.com}}"
  DEPLOYMENTS="$CONTRACTS/deployments/sepolia.json"
  if [ ! -f "$DEPLOYMENTS" ]; then
    echo "ERROR: $DEPLOYMENTS not found. Run 'make deploy-sepolia' first." >&2
    exit 1
  fi
  step "2. Connecting to Ethereum Sepolia Testnet..."
  wait_rpc "$RPC_URL"

  NAMESPACE="$(node -pe 'require("'"$DEPLOYMENTS"'").contracts.NamespaceDApp')"
  REGISTRY="$(node -pe 'require("'"$DEPLOYMENTS"'").contracts.RecordSchemaRegistry')"
  RESOLVER_REG="$(node -pe 'require("'"$DEPLOYMENTS"'").contracts.ResolverRegistry')"
  RESOLVER_INC="$(node -pe 'require("'"$DEPLOYMENTS"'").contracts.ResolverIncentives')"

  step "3. Starting Resolver daemon on Sepolia..."
  RPC_URL="$RPC_URL" CONTRACT_ADDRESS="$NAMESPACE" REGISTRY_ADDRESS="$REGISTRY" \
    RESOLVER_KEYSTORE="$DATA_DIR/resolver.key" DATA_DIR="$DATA_DIR/resolver" ALLOW_PEER_HINTS=true \
    DEPLOYMENTS="$DEPLOYMENTS" ENABLE_SHOWCASE=true DDNS_NETWORK="sepolia" \
    "$DATA_DIR/bin/resolver" >"$DATA_DIR/resolver.log" 2>&1 &
  PIDS+=($!)
  wait_for "$REST/healthz" "resolver"

else
  RPC_URL="http://127.0.0.1:8545"
  ALICE_PK="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
  DEPLOYMENTS="$CONTRACTS/deployments/localhost.json"

  step "2. Starting local blockchain (Hardhat)..."
  free_port 8545
  ( cd "$CONTRACTS" && npx hardhat node --hostname 127.0.0.1 >"$DATA_DIR/chain.log" 2>&1 ) &
  PIDS+=($!)
  wait_rpc "$RPC_URL"

  step "3. Deploying smart contracts..."
  ( cd "$CONTRACTS" && npx hardhat run scripts/deploy.ts --network localhost >/dev/null )
  ( cd "$CONTRACTS" && npx hardhat run scripts/seed.ts --network localhost >/dev/null )

  NAMESPACE="$(node -pe 'require("'"$DEPLOYMENTS"'").contracts.NamespaceDApp')"
  REGISTRY="$(node -pe 'require("'"$DEPLOYMENTS"'").contracts.RecordSchemaRegistry')"

  step "4. Starting Resolver daemon on Localhost..."
  RPC_URL="$RPC_URL" CONTRACT_ADDRESS="$NAMESPACE" REGISTRY_ADDRESS="$REGISTRY" \
    RESOLVER_KEYSTORE="$DATA_DIR/resolver.key" DATA_DIR="$DATA_DIR/resolver" ALLOW_PEER_HINTS=true \
    DEPLOYMENTS="$DEPLOYMENTS" ENABLE_SHOWCASE=true \
    "$DATA_DIR/bin/resolver" >"$DATA_DIR/resolver.log" 2>&1 &
  PIDS+=($!)
  wait_for "$REST/healthz" "resolver"

  export DDNS_PRIVATE_KEY="$ALICE_PK"
  export DDNS_DEPLOYMENTS="$DEPLOYMENTS"
  export DDNS_RESOLVER="$REST"

  ddns announce-resolver --endpoint "$REST" >/dev/null 2>&1 || true
fi

clear 2>/dev/null || true
echo -e "\033[1;32m========================================================================\033[0m"
echo -e "\033[1;32m  Decentralized DNS — Node & Resolver Services Active                  \033[0m"
echo -e "\033[1;32m========================================================================\033[0m"
echo ""
echo -e "\033[1;36mEndpoints:\033[0m"
echo ""
echo -e "  1. \033[1;33mShowcase & DApp Interface:\033[0m"
echo -e "     \033[4;34mhttp://localhost:8080/showcase/\033[0m"
echo ""
echo -e "  2. \033[1;33mResolver Admin Telemetry:\033[0m"
echo -e "     \033[4;34mhttp://localhost:8080/admin\033[0m"
echo ""
echo -e "  3. \033[1;33mDecentralized Web Gateway:\033[0m"
echo -e "     \033[4;34mhttp://localhost:8080/web/<domain>\033[0m"
echo ""
echo -e "\033[1;30mPress Ctrl+C anytime to stop all services.\033[0m"
echo ""

while true; do
  sleep 1
done
