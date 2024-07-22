library;

use std::{bytes::Bytes, vm::evm::evm_address::EvmAddress};

abi AggregationIsm {
    #[storage(read)]
    fn threshold(domain: u32) -> u8;
    #[storage(read)]
    fn modules(domain: u32) -> Vec<ContractId>;
    #[storage(read)]
    fn modules_and_threshold(message: Bytes) -> (Vec<ContractId>, u8);
    #[storage(read)]
    fn is_enrolled(domain: u32, module: ContractId) -> bool;

    #[storage(read, write)]
    fn enroll_module(domain: u32, modules: ContractId);
    #[storage(read, write)]
    fn enroll_modules(domains: Vec<u32>, modules: Vec<Vec<ContractId>>);
    #[storage(read, write)]
    fn unenroll_module(domain: u32, module: ContractId);
    #[storage(read, write)]
    fn set_threshold(domain: u32, threshold: u8);
    #[storage(read, write)]
    fn set_thresholds(domains: Vec<u32>, thresholds: Vec<u8>);
}
