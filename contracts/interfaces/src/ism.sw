library;

use std::bytes::Bytes;

pub enum ModuleType {
    UNUSED_0: (),
    ROUTING: (),
    AGGREGATION: (),
    LEGACY_MULTISIG: (),
    MULTISIG: (),
}

abi InterchainSecurityModule {
    #[storage(read, write)]
    fn verify(metadata: Bytes, message: Bytes) -> bool;

    // Returns an enum that represents the type of security model
    // encoded by this ISM. Relayers infer how to fetch and format metadata.
    #[storage(read)]
    fn module_type() -> ModuleType;
}
