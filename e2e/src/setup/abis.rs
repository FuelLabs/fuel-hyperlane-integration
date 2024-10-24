use fuels::prelude::*;

abigen!(
    Contract(
        name = "Mailbox",
        abi = "contracts/mailbox/out/debug/mailbox-abi.json",
    ),
    Contract(
        name = "InterchainGasPaymaster",
        abi = "contracts/igp/gas-paymaster/out/debug/gas-paymaster-abi.json",
    ),
    Contract(
        name = "GasOracle",
        abi = "contracts/igp/gas-oracle/out/debug/gas-oracle-abi.json",
    ),
    Contract(
        name = "IGPHook",
        abi = "contracts/hooks/igp/out/debug/igp-hook-abi.json",
    ),
    Contract(
        name = "WarpRoute",
        abi = "contracts/warp-route/out/debug/warp-route-abi.json",
    ),
    Contract(
        name = "MerkleTreeHook",
        abi = "contracts/hooks/merkle-tree-hook/out/debug/merkle-tree-hook-abi.json",
    ),
    Contract(
        name = "ValidatorAnnounce",
        abi = "contracts/validator-announce/out/debug/validator-announce-abi.json",
    ),
    Contract(
        name = "AggregationISM",
        abi = "contracts/ism/aggregation-ism/out/debug/aggregation-ism-abi.json",
    ),
    Contract(
        name = "MessageIdMultisigISM",
        abi = "contracts/ism/multisig/message-id-multisig-ism/out/debug/message-id-multisig-ism-abi.json",
    ),
    Contract(
        name = "MerkleRootMultisigISM",
        abi = "contracts/ism/multisig/merkle-root-multisig-ism/out/debug/merkle-root-multisig-ism-abi.json",
    ),
    Contract(
        name = "DomainRoutingISM",
        abi = "contracts/ism/routing/domain-routing-ism/out/debug/domain-routing-ism-abi.json",
    ),
    Contract(
        name = "DefaultFallbackDomainRoutingISM",
        abi = "contracts/ism/routing/default-fallback-domain-routing-ism/out/debug/default-fallback-domain-routing-ism-abi.json",
    ),
    Contract(
      name = "MsgRecipient",
      abi = "contracts/test/msg-recipient-test/out/debug/msg-recipient-test-abi.json"
  ),
);
