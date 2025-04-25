# Fuel Hyperlane Integration

This repository contains the Sway contracts for the Hyperlane Protocol.

## Glossary

The repository is structured as follows:

- `contracts`: Contains the Sway interfaces and contracts for the Hyperlane Protocol.
- `deploy`: Contains the deployment and initialization script for the Hyperlane Protocol.
- `e2e`: Contains the E2E tests for the Hyperlane Protocol.
- `demo`: Contains the testnet E2E cases for all the Hyperlane contracts.
- `infra`: Contains the configuration files and scripts for running the Hyperlane Protocol infrastructure.
- `test-utils`: Contains utility functions for testing the Hyperlane Protocol.

### Contracts

The following Hyperlane contracts with their respective interfaces have been implemented:

- `Mailbox`: The core contract for sending and receiving messages passed through the Hyperlane Protocol.
- Interchain Gas Payment _(IGP)_:
  - `InterchainGasPaymaster`: Allows the payment of gas fees for cross-chain transactions.
  - `GasOracle`: Provides gas price information for the `InterchainGasPaymaster`.
- Interchain Security Modules _(ISM)_:
  - Multisig ISM
    - `MessageIdMultisigISM`: A multisig ISM that requires a threshold of signers to approve a message.
    - `MerkleRootMultisigISM`: A more robust multisig ISM that requires a threshold of signers to approve a message and uses a Merkle Tree to store messages.
  - Routing ISM
    - `DomainRoutingISM`: Routes to different ISMs based on the domain of the message.
    - `DefaultFallbackDomainRoutingISM`: Routes to a different ISMs based on the domain of the message and falls back to a default ISM if no domain-specific ISM is found.
  - `PausableISM`: Allows the pausing any execution which invokes the ISM.
  - `AggregatedISM`: Allows the usage of multiple ISMs for a single message.
- Post Dispatch Hooks:
  - `AggregationHook`: Aggregates the logic of multiple hooks.
  - `FallbackDomainRoutingHook`: Routes to a different hook based on the domain of the message and falls back to a default hook if no domain-specific hook is found.
  - `IGP`: Used with the `InterchainGasPaymaster` to allow the payment of gas fees for cross-chain transactions.
  - `MerkleTreeHook`: Used with the `MerkleRootMultisigISM` to store messages in a Merkle Tree.
  - `PausableHook`: Allows the pausing of any execution which invokes the hook.
  - `ProtocolFeeHook`: Allows the collection of protocol fees for the Hyperlane Protocol.
- `ValidatorAnnounce`: Allows validators to announce their signature location to the relayer.
- `WarpRoutes`: Allows transferring tokens between different chains using the Hyperlane Protocol.

Contracts used for testing can be found in the `test` and `mocks` directories.

Official Hyperlane protocol interfaces can be found in the `interfaces` directory.

More detailed information about the contracts can be found in the Hyperlane Protocol [documentation](https://docs.hyperlane.xyz/docs/protocol/protocol-overview).

## Notes

- Due to Fuel not having token approvals, when utilizing WarpRoute contracts, the tokens and the transfer are sent as 2 separate transactions. In order to avoid the risk of being frontrun, a multicall should be used to execute the two transactions atomically.
- Due to the way decimal conversion is handled on the IGP contract, the biggest precision delta recommened between the two chains is 18 decimals. This is to ensure that the gas price does not overflow in the calculation as it's limited to a `u64`, which is the higest value that is supported by the Fuel SRC20 interface. _Reference at hooks/gas-paymaster/src/main.sw#L546_

## Setup

The Fuel toolchain and prerequisites are required to build the contracts.
Setup instructions can be found in the [official guide](https://docs.fuel.network/guides/installation/).

After installing the Fuel toolchain, you can build the contracts by running:

```bash
forc build
```

## Deployment

The deployment scripts for the Hyperlane Protocol can be found in the `deploy` directory.

The script for deploying the Hyperlane Protocol can be run by executing:

```bash
cd deploy
cargo run -- <network> <dump_path>
```

For the `network` argument, two values are accepted:

- `LOCAL`: Deploys the contracts to a locally running `fuel-core` instance.
- `TESTNET`: Deploys the contracts to the Fuel Testnet.

The `dump_path` argument specifies the path to the write all the deployed contract addresses.
It is an optional param which will default to the `deployments` folder of the `deploy` directory.

In order to run the deployment script, the `.env` file must be populated.
The parameters required can be found in the `.env.example` file, in the root of the `deploy` directory.

The `FUEL_PRIVATE_KEY` parameter is the Fuel account which will be the deployer and owner (if the contract is ownable) of the contracts.
There are three `SEPOLIA_PRIVATE_KEY` parameters which are the EVM accounts that will be set as the validators of the deployed MultisigISM contracts.

## Testing

The repository contains unit tests written in Sway and Rust, as well as a comprehensive E2E test suite.

### Sway Unit Tests

To run the Sway unit tests, execute:

```bash
forc test
```

### Rust Unit Tests

To run the Rust unit tests, execute:

```bash
cargo test
```

### E2E Tests

#### Prerequisites

- The `hyperlane-cli` must be installed - [Link](https://www.npmjs.com/package/@hyperlane-xyz/cli).
- The `anvil` node must be installed - [Link](https://book.getfoundry.sh/getting-started/installation).
- `yq` must be installed - [Link](https://formulae.brew.sh/formula/yq#default).
- `jq` must be installed - [Link](https://formulae.brew.sh/formula/jq#default).

In order to have funds on the local Fuel node which is required for the E2E tests, there should be an entry added to `infra/configs/local-fuel-snapshot/state_config.json`

It can be added like so:

```json
{
  "tx_id": "0000000000000000000000000000000000000000000000000000000000000004", // Must be one higher than the previous entry
  "output_index": 0,
  "tx_pointer_block_height": 0,
  "tx_pointer_tx_idx": 0,
  "owner": "ccae08f2eb25ce643496b0d0857f35dcfd0b30d5841ea10a078b79438c32ae07", // Your wallet public address, no 0x prefix
  "amount": 1152921504606846976,
  "asset_id": "0xf8f8b6283d7fa5b672b530cbb84fcccb4ff8dc40f8176ef4544ddb1f1952ad07"
}
```

#### Running the E2E Tests

The E2E tests include test cases which are executed on a local `fuel-core` instance and EVM `anvil` instance.

Running the nodes and hyperlane infrastructure can be done by running the following script from the `infra` directory:

```bash
bash ./run.sh --env LOCAL --agent RELAYER
```

After the relayer is started, the E2E tests can be executed in a separate terminal window by moving to the `e2e` directory and executing:

```bash
cargo run
```

#### Troubleshooting

##### NotOwner Error

Make sure the fuel private key in the `.env` file is the same in both the `e2e` and `deploy` directories.

##### MerkleTreeHook invalid address

- During the `hyerlane-cli` deployment, locate the `MerkleTreeHook` contract being deployed on the `anvil` instance and update line `285` of the `infra/run.sh` script with the correct address.

```bash
export HYP_CHAINS_TEST1_MERKLETREEHOOK="contract-address-from-your-local-depolyment"
```

After that, re-run the `infra/run.sh` script.

## Demo

The repository contains a demo that showcases the Hyperlane Protocol on live testnets. The demo includes E2E cases for all of the Hyperlane components interacting between Base Sepolia and Fuel Testnet.

### Running the Demo

Before running the demo, the `.env` files of both the `demo` and the `deploy` directories must be populated with the required parameters.

For the `BaseSepolia` RPCs, we recommend something without a limit on the number of requests.
For the Private Keys, remember to have testnet funds in for both `FuelTestnet` and `BaseSepolia`.

For running the Validators required, the `SEPOLIA_PRIVATE_KEY` parameters from the `deploy/.env` file must be copied to the `infra/run-val.sh` script _in the same order as described by the comments_. Make sure the private keys are different for each validator.

**Note:** Sepolia addresses in `deploy/env` should be without 0x prefix, but all the addresses in `infra/run-val.sh` script should have 0x prefix.

After all the private keys and RPC urls are set, the Sway smart contracts need to be deployed on `FuelTestnet`, this can be done using the deploy script:

```bash
cd deploy
cargo run -- TESTNET
```

After the script is done, the contract addresses will be written to the `deployments` folder. These contracts need to be copied over to the agent configuration files in the `infra` directory.

The file to edit is `infra/configs/agent-configs.json` and the contract addresses need to be set on the `fueltestnet` network.

In the output logs of the deployment, there also be a `Config Sync Block` output, this block needs to be set in the `infra/configs/agent-configs.json` file under the `fueltestnet` network, `"index" : { "from": <block_number> }`.

After the contracts and sync block are set, the demo can be run by executing:

```bash
bash ./infra/run.sh --env TESTNET --agent RELAYER
bash ./infra/run-val.sh --network fueltestnet --number 1
bash ./infra/run-val.sh --network basesepolia --number 1
bash ./infra/run-val.sh --network basesepolia --number 2
bash ./infra/run-val.sh --network basesepolia --number 3
cd ./demo
cargo run
```

_Note: separate terminals are required for each of the `run-val.sh`, `run.sh` and `cargo run` scripts, unless running in detached mode_
