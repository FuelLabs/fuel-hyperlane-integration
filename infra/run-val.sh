NETWORK=""
NUMBER=""
METRICS_PORT=9090


while [[ "$#" -gt 0 ]]; do
    case $1 in
        --network)
            NETWORK="$2"
            shift 2
            ;;
        --number)
            NUMBER="$2"
            shift 2
            ;;
        *)
            echo "Unknown parameter: $1"
            ;;
    esac
done

case $NUMBER in
    1)
        SEPOLIA_SIGNER_KEY="YOUR_EVM_PRIVATE_KEY" # SEPOLIA_PRIVATE_KEY_1 of the `deploy` dir `.env` file
        METRICS_PORT=9094
        shift 2
        ;;
    2)
        SEPOLIA_SIGNER_KEY="YOUR_EVM_PRIVATE_KEY" # SEPOLIA_PRIVATE_KEY_2 of the `deploy` dir `.env` file
        METRICS_PORT=9095
        shift 2
        ;;
    3)
        SEPOLIA_SIGNER_KEY="YOUR_EVM_PRIVATE_KEY" # SEPOLIA_PRIVATE_KEY_3 of the `deploy` dir `.env` file
        METRICS_PORT=9096
        shift 2
        ;;
    *)
        echo "Unknown parameter: $1"
        ;;
esac

PROJECT_ROOT=$(git rev-parse --show-toplevel)
PROJECT_DIR="$PROJECT_ROOT/infra/hyperlane-monorepo/rust/main"
export CONFIG_FILES="$PROJECT_ROOT/infra/configs/agent-config.json"
DB_DIR="./validator_db_"$NETWORK"_"$NUMBER""
export VALIDATOR_SIGNATURES_DIR="./validator_signatures_"$NETWORK"_"$NUMBER""
VALIDATOR_CHAIN=$NETWORK
FUEL_SIGNER_KEY="YOUR_FUEL_PRIVATE_KEY" # FUEL_PRIVATE_KEY of the `deploy` dir `.env` file
LOG_PATH="$PROJECT_DIR/validator_"$NETWORK"_"$NUMBER".log"
touch "$LOG_PATH"

kill_processes() {
    if [ -n "$VALIDATOR_PID" ]; then
        echo "Killing $NETWORK $NUMBER Validator process with PID $VALIDATOR_PID"
        kill $VALIDATOR_PID
    fi
}

trap kill_processes EXIT

cd $PROJECT_DIR

if [ "$NETWORK" = "fueltestnet" ]; then
    export HYP_DEFAULTSIGNER_KEY="$FUEL_SIGNER_KEY"
else
    export HYP_DEFAULTSIGNER_KEY="$SEPOLIA_SIGNER_KEY"
fi

export RUST_BACKTRACE=1


    cargo run --release --bin validator -- \
        --db "$DB_DIR" \
        --originChainName "$VALIDATOR_CHAIN" \
        --checkpointSyncer.type localStorage \
        --checkpointSyncer.path "$VALIDATOR_SIGNATURES_DIR" \
        --validator.key "$SEPOLIA_SIGNER_KEY" \
        --metrics-port $METRICS_PORT \
        > "$LOG_PATH" 2>&1 &

VALIDATOR_PID=$!


tail -f "$LOG_PATH"

