# Requirements

- [Hyperlane CLI](www.example.com)
- [Anvil](www.example.com)
- [Fuel Toolchain](www.example.com)
- [YQ](www.example.com)
- [JQ](www.example.com)
- [BASH v4](www.example.com)

# Setup

```bash
npm install -g @fuel-infrastructure/fuel-hyperlane-cli
curl -L https://foundry.paradigm.xyz | bash
foundryup
brew install yq
brew install jq
brew install bash
exec zsh
```

# Populate the env

```bash
cp .env.example .env
```

Make sure every private/public key has a **0x** in front of it.

# Run the infra

ENV: LOCAL, TESTNET
AGENT: RELAYER, VALIDATOR

Example:

```bash
forc build

bash infra/run.sh --env LOCAL --agent RELAYER
bash infra/run.sh --env LOCAL --agent VALIDATOR
```

**NOTE: change HYP_CHAINS_TEST1_MERKLETREEHOOK in run.sh**
