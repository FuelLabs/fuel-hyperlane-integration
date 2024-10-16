#!/bin/bash

PROJECT_ROOT=$(git rev-parse --show-toplevel)
BLOCK_SCRIPT_PATH=$PROJECT_ROOT/demo/update-blocks.sh
DEMO_PATH=$PROJECT_ROOT/demo
# CONFIG_PATH=$PROJECT_ROOT/infra/configs/agent-config.json

cd $DEMO_PATH

cargo run -- $BLOCK_SCRIPT_PATH