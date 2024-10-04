# Requirements

- [Hyperlane CLI](www.example.com)
- [Anvil](www.example.com)
- [Fuel Toolchain](www.example.com)
- [YQ](www.example.com)
- [JQ](www.example.com)
- [BASH v4](www.example.com)

# Populate the env

```bash
cp .env.example .env
```

# Run the infra

ENV: LOCAL, TESTNET
AGENT: RELAYER, VALIDATOR

Example:

```bash
bash infra/run.sh --env LOCAL --agent RELAYER
bash infra/run.sh --env LOCAL --agent VALIDATOR
```
