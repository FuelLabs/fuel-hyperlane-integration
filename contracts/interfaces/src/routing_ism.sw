library;

use std::{bytes::Bytes, vm::evm::evm_address::EvmAddress};

abi RoutingIsm {
    #[storage(read)]
    fn route(message: Bytes) -> ContractId;
}
