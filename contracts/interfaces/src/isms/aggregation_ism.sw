library;

use std::{bytes::Bytes, vm::evm::evm_address::EvmAddress};

//  Official Aggregation ISM interface for Hyperlane V3
abi AggregationIsm {
    #[storage(read)]
    fn modules_and_threshold(message: Bytes) -> (Vec<ContractId>, u8);
}

//  Additional functions added for the fully functional implementation of the Aggregation ISM
abi AggregationIsmFunctions {
    #[storage(read, write)]
    fn initialize(owner: b256);

    #[storage(write)]
    fn set_threshold(threshold: u8);

    #[storage(write)]
    fn enroll_module(module: ContractId);
}
