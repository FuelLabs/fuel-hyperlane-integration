#!/bin/bash

# Check if hyperlane cli is installed globally
# TODO either have for all deps or list deps in a README
if npm list -g | grep -q "@hyperlane-xyz/cli"; then
    echo "@hyperlane-xyz/cli is already installed."
else
    echo "@hyperlane-xyz/cli is not installed. Installing..."
    npm install -g @hyperlane-xyz/cli
fi

# Private key of the first Anvil account
HYP_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Start the EVM anvil node in the background
anvil &> /dev/null &

# Save the PID of the last background process (anvil)
ANVIL_PID=$!
echo "Anvil is running with PID $ANVIL_PID"

# Deploy the contracts to the EVM node
hyperlane core deploy --private-key $HYP_KEY -y --chain anvil8545 --overrides ./configs


sleep 5
# Kill the Anvil process after the work is done
echo "Killing Anvil process with PID $ANVIL_PID"
kill $ANVIL_PID