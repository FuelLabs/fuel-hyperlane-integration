#!/bin/bash

# Cleanup
kill_processes() {
    if [ -n "$ANVIL_PID" ]; then
        echo "Killing Anvil process with PID $ANVIL_PID"
        kill $ANVIL_PID
    fi

    if [ -n "$FUEL_CORE_PID" ]; then
        echo "Killing Fuel Core process with PID $FUEL_CORE_PID"
        kill $FUEL_CORE_PID
    fi

    if [ -n "$RELAYER_PID" ]; then
        echo "Killing Relayer process with PID $RELAYER_PID"
        kill $RELAYER_PID
    fi

    if [ -n "$VALIDATOR_PID" ]; then
        echo "Killing Validator process with PID $VALIDATOR_PID"
        kill $VALIDATOR_PID
    fi
rm -rf $OUTPUT_PATH
}

trap kill_processes EXIT

# Default values for variables
ENVIRONMENT=""
AGENT=""

# Validation
usage() {
    echo "Usage: $0 --env <LOCAL|TESTNET> --agent <RELAYER|VALIDATOR>"
    exit 1
}
validate_env() {
    if [[ "$ENVIRONMENT" != "LOCAL" && "$ENVIRONMENT" != "TESTNET" ]]; then
        echo "Error: Invalid environment. Only 'LOCAL' or 'TESTNET' are allowed."
        exit 1
    fi
}
validate_agent() {
    if [[ "$AGENT" != "RELAYER" && "$AGENT" != "VALIDATOR" ]]; then
        echo "Error: Invalid agent. Only 'RELAYER' or 'VALIDATOR' are allowed."
        exit 1
    fi
}

# Parse the command-line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --env)
            ENVIRONMENT="$2"
            shift 2
            ;;
        --agent)
            AGENT="$2"
            shift 2
            ;;
        *)
            echo "Unknown parameter: $1"
            usage
            ;;
    esac
done

if [[ -z "$ENVIRONMENT" || -z "$AGENT" ]]; then
    echo "Error: Both --env and --agent arguments are required."
    usage
fi

validate_env
validate_agent

echo "Setting up infrastructure for $ENVIRONMENT."

# Paths
PROJECT_ROOT=$(git rev-parse --show-toplevel)
INFRA_PATH="$PROJECT_ROOT/infra"
OUTPUT_PATH="$INFRA_PATH/output"
MONOREPO_PATH="$INFRA_PATH/hyperlane-monorepo"
ENV_FILE="$INFRA_PATH/.env"

load_env_file() {
    if [ -f "$ENV_FILE" ]; then
        source "$ENV_FILE"
    else
        echo "Error: .env file not found in $INFRA_PATH. Exiting..."
        exit 1
    fi
}

check_env_var() {
    local var_name="$1"
    if [ -z "${!var_name}" ]; then
        echo "Error: $var_name is not set or empty. Exiting..."
        exit 1
    fi
}

# Load .env file and check required variables
load_env_file
required_vars=("FUEL_SIGNER_KEY" "SEPOLIA_SIGNER_KEY" "SEPOLIA_SIGNER_ADDRESS")
for var in "${required_vars[@]}"; do
    check_env_var "$var"
done
echo "All required environment variables are set."

# Check if monorepo exists, clone if not
if [ ! -d "$MONOREPO_PATH" ]; then
    echo "Monorepo not found. Cloning..."
    git clone --branch feat/fuel-integration --single-branch https://github.com/fuel-infrastructure/hyperlane-monorepo "$MONOREPO_PATH"
else
    echo "Monorepo found."
fi


ANVIL_PID=""
FUEL_CORE_PID=""

if [ "$ENVIRONMENT" == "LOCAL" ]; then
    # Paths
    FUEL_LOCAL_SNAPSHOT="$INFRA_PATH/configs/local-fuel-snapshot"
    FUNDED_ANVIL_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    HYP_KEY="$FUNDED_ANVIL_PRIVATE_KEY"
    ANVIL_OUTPUT="$OUTPUT_PATH/nodes/anvil_output.log"
    FUEL_CORE_OUTPUT="$OUTPUT_PATH/nodes/fuelcore_output.log"
    HYP_CLI_CORE_CONFIGS="$INFRA_PATH/configs/core-config.yaml"
    LOCAL_FUEL_CONTRACT_DUMP="$OUTPUT_PATH/contracts"

    mkdir -p "$OUTPUT_PATH/nodes"
    touch "$ANVIL_OUTPUT" "$FUEL_CORE_OUTPUT"

    # Update YAML configuration for contract owner
    update_core_config() {
        local key="$1"
        local value="$2"
        yq eval ".$key = \"$value\"" -i "$HYP_CLI_CORE_CONFIGS"
    }
    
    echo "Updating hyperlane deployment configurations with Sepolia signer address..."
    update_core_config "owner" "$SEPOLIA_SIGNER_ADDRESS"
    update_core_config "requiredHook.owner" "$SEPOLIA_SIGNER_ADDRESS"

    start_anvil() {
        echo "Starting Anvil node..."
        anvil &> "$ANVIL_OUTPUT" &
        ANVIL_PID=$!
        echo "Anvil is running with PID $ANVIL_PID"
    }

    start_fuel_core() {
        echo "Starting Fuel Core node..."
        fuel-core run --db-type in-memory --debug --snapshot "$FUEL_LOCAL_SNAPSHOT" &> "$FUEL_CORE_OUTPUT" &
        FUEL_CORE_PID=$!
        echo "Fuel Core is running with PID $FUEL_CORE_PID"
    }

    wait_for_log() {
        local logfile="$1"
        local pattern="$2"
        while ! grep -q "$pattern" "$logfile"; do
            sleep 0.5
        done
    }

    # Start local nodes
    start_anvil
    start_fuel_core

    echo "Waiting for nodes to be ready..."
    wait_for_log "$ANVIL_OUTPUT" "Listening on 127.0.0.1:8545"
    wait_for_log "$FUEL_CORE_OUTPUT" "Starting GraphQL_Off_Chain_Worker service"

    # Deploy Hyperlane Core and contracts
    echo "Deploying Hyperlane Core..."
    ANVIL_DEPLOYMENT_DUMP="$INFRA_PATH/configs/chains/anvil8545/addresses.yaml"
    LOG_LEVEL="TRACE"  hyperlane core deploy --private-key "$HYP_KEY" -y --chain anvil8545 --overrides "$INFRA_PATH/configs" --config "$HYP_CLI_CORE_CONFIGS"

    echo "Deploying FuelVM contracts..."
    cd "$PROJECT_ROOT/deploy" && RUSTFLAGS="-Awarnings" cargo run -- LOCAL "$LOCAL_FUEL_CONTRACT_DUMP"

    # Write deployments to configs
    echo "Writing deployments to configs..."
    LOCAL_CONFIG_FILE="$INFRA_PATH/configs/agent-config-local.json"

    LOCAL_FUEL_CONTRACT_DUMP_FULL="$LOCAL_FUEL_CONTRACT_DUMP/local/contract_addresses.yaml"

# Paths to contract dumps and config file
LOCAL_FUEL_KEYS=("interchainGasPaymaster" "interchainSecurityModule" "mailbox" "merkleTreeHook" "validatorAnnounce")
LOCAL_ANVIL_KEYS=("domainRoutingIsmFactory" "interchainAccountIsm" "interchainAccountRouter" "mailbox" "proxyAdmin" "staticAggregationHookFactory" "staticAggregationIsmFactory" "staticMerkleRootMultisigIsmFactory" "staticMessageIdMultisigIsmFactory" "testRecipient" "validatorAnnounce")

# Read fuel data
declare -A FUEL_VALUES
for key in "${LOCAL_FUEL_KEYS[@]}"; do
    FUEL_VALUES[$key]=$(yq e ".$key" "$LOCAL_FUEL_CONTRACT_DUMP_FULL")
done

# Read anvil data
declare -A ANVIL_VALUES
for key in "${LOCAL_ANVIL_KEYS[@]}"; do
    ANVIL_VALUES[$key]=$(yq e ".$key" "$ANVIL_DEPLOYMENT_DUMP")
done

# Write fuel data to config file
for key in "${LOCAL_FUEL_KEYS[@]}"; do
    yq e ".chains.fueltest1.$key = \"${FUEL_VALUES[$key]}\"" "$LOCAL_CONFIG_FILE" -i
done

# Write anvil data to config file
for key in "${LOCAL_ANVIL_KEYS[@]}"; do
    yq e ".chains.test1.$key = \"${ANVIL_VALUES[$key]}\"" "$LOCAL_CONFIG_FILE" -i
done

fi



# Paths and settings
LOG_PATH=""
DB_DIR=""
RELAY_CHAINS=""
VALIDATOR_CHAIN=""
mkdir -p "$OUTPUT_PATH/agents"

# Environment-specific settings
set_environment_config() {
    if [ "$ENVIRONMENT" == "TESTNET" ]; then
        RELAY_CHAINS="fueltestnet,sepolia"
        VALIDATOR_CHAIN="fueltestnet"
        export CONFIG_FILES="$INFRA_PATH/configs/agent-config.json"
    else
        RELAY_CHAINS="fueltest1,test1"
        VALIDATOR_CHAIN="fueltest1"
        export CONFIG_FILES="$INFRA_PATH/configs/agent-config-local.json"
    fi
}

# Function to set common variables for agents
set_common_agent_vars() {
    LOG_PATH="$OUTPUT_PATH/agents/$1.log"
    DB_DIR="$OUTPUT_PATH/agents/hyperlane_db_$1_$VALIDATOR_CHAIN"
    touch "$LOG_PATH"
}

# Function to run relayer
run_relayer() {

    # TODO fix this temp workaround if needed
    export GASPAYMENTENFORCEMENT="[{\"type\": \"none\"}]"
    export HYP_CHAINS_TEST1_MERKLETREEHOOK="0x8A791620dd6260079BF849Dc5567aDC3F2FdC318"
    export HYP_CHAINS_TEST1_INTERCHAINGASPAYMASTER="0x0000000000000000000000000000000000000000"


    cargo run --release --bin relayer -- \
        --db "$DB_DIR" \
        --relayChains "$RELAY_CHAINS" \
        --allowLocalCheckpointSyncers true \
        --defaultSigner.key "$FUEL_SIGNER_KEY" \
        --chains.fueltestnet.signer.key "$FUEL_SIGNER_KEY" \
        --chains.sepolia.signer.key "$SEPOLIA_SIGNER_KEY" \
        --metrics-port 9091 \
        > "$LOG_PATH" 2>&1 &
    RELAYER_PID=$!
    tail -f "$LOG_PATH"
}

# Function to run validator
run_validator() {
    export VALIDATOR_SIGNATURES_DIR="$OUTPUT_PATH/hyperlane-validator-signatures-$VALIDATOR_CHAIN"
    export HYP_DEFAULTSIGNER_KEY="$FUEL_SIGNER_KEY"

    cargo run --release --bin validator -- \
        --db "$DB_DIR" \
        --originChainName "$VALIDATOR_CHAIN" \
        --checkpointSyncer.type localStorage \
        --checkpointSyncer.path "$VALIDATOR_SIGNATURES_DIR" \
        --validator.key "$SEPOLIA_SIGNER_KEY" \
        > "$LOG_PATH" 2>&1 &
    VALIDATOR_PID=$!
    tail -f "$LOG_PATH"
}

# Main logic
set_environment_config
cd "$MONOREPO_PATH/rust/main"

if [ "$AGENT" == "RELAYER" ]; then
    set_common_agent_vars "relayer"
    run_relayer
else [ "$AGENT" == "VALIDATOR" ]; 
    set_common_agent_vars "validator"
    run_validator
fi


