# Fuel Hyperlane Integration

This repository contains the Sway contracts for the Hyperlane Protocol.

## Glossary

The repository is structured as follows:

- `contracts`: Contains the Sway interfaces and contracts for the Hyperlane Protocol.
- `deploy`: Contains the deployment scripts for the Hyperlane Protocol.
- `e2e`: Contains the E2E tests for the Hyperlane Protocol.
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
  - `AggregatedISM`: Allows the usage of multiple ISMs for a single message.
- Post Dispatch Hooks:
  - `IGP`: Used with the `InterchainGasPaymaster` to allow the payment of gas fees for cross-chain transactions.
  - `MerkleTreeHook`: Used with the `MerkleRootMultisigISM` to store messages in a Merkle Tree.
- `ValidatorAnnounce`: Allows validators to announce their signature location to the relayer.
- `WarpRoutes`: Allows transferring tokens between different chains using the Hyperlane Protocol.

Contracts used for testing can be found in the `test` and `mocks` directories.

Official Hyperlane protocol interfaces can be found in the `interfaces` directory.

More detailed information about the contracts can be found in the Hyperlane Protocol [documentation](https://docs.hyperlane.xyz/docs/protocol/protocol-overview).

## Setup

The Fuel toolchain and prerequisites are required to build the contracts.
Setup instructions can be found in the [official guide](https://docs.fuel.network/guides/installation/).

After installing the Fuel toolchain, you can build the contracts by running:

```bash
$ forc build
```

## Testing

The repository contains unit tests written in Sway and Rust, as well as a comprehensive E2E test suite.

### Sway Unit Tests

To run the Sway unit tests, execute:

```bash
$ forc test
```

### Rust Unit Tests

To run the Rust unit tests, execute:

```bash
$ cargo test
```

### E2E Tests

To run the E2E tests, execute:

TODO: Running the infra, stuff that needs to be installed, other details

```bash
$ cd e2e
$ cargo run
```

## Deployment

The deployment scripts for the Hyperlane Protocol can be found in the `deploy` directory.

TODO: setup deploy and deployment instructions
