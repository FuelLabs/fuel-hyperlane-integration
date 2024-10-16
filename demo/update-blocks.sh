#!/bin/bash


# Fetch the latest block height from the Fuel network
fuel_response=$(curl -s -X POST 'https://testnet.fuel.network/v1/graphql' \
  -H 'Content-Type: application/json' \
  -d '{"query":"query Transactions { chain { latestBlock { height } } }"}')

# Parse the number from the response using jq
fuel_block=$(echo "$fuel_response" | jq -r '.data.chain.latestBlock.height')

# Fetch the latest block number from the Sepolia network
sepolia_response=$(curl -s -X POST 'https://11155111.rpc.thirdweb.com' \
  -H 'Content-Type: application/json' \
  -d '{"method": "eth_blockNumber", "jsonrpc": "2.0", "id": 1}')

sepolia_block=$(echo "$sepolia_response" | jq -r '.result' | xargs printf "%d")

echo "Fuel block: $fuel_block"
echo "Sepolia block: $sepolia_block"

return 0

# {"jsonrpc":"2.0","id":1,"result":"0x68a077"}



sepolia_block=$1
fuel_block=$2


PROJECT_ROOT=$(git rev-parse --show-toplevel)
CONFIG_PATH=$PROJECT_ROOT/infra/configs/agent-config.json

yq e ".chains.fueltestnet.index.from = $fuel_block" "$CONFIG_PATH" -i
yq e ".chains.sepolia.index.from = $sepolia_block" "$CONFIG_PATH" -i

echo "Updated blocks for sepolia and fueltestnet"
