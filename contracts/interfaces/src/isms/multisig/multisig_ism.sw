library;

use std::{bytes::Bytes, vm::evm::evm_address::EvmAddress};

// Official Multisig ISM interface for Hyperlane V3
abi MultisigIsm {    
    #[storage(read)]
    fn validators_and_threshold(message: Bytes) -> (Vec<EvmAddress>, u8);

    fn digest(metadata: Bytes, message: Bytes) -> Bytes;

    fn signature_at(metadata: Bytes, index: u32) -> Bytes;
}

// Additional functions added for the fully functional implementation of the Multisig ISM
abi MultisigIsmFunctions {
    #[storage( write)]
    fn enroll_validator(validator: EvmAddress);

    #[storage( write)]
    fn set_threshold(threshold: u8);
}
