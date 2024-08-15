library;

use std::bytes::Bytes;

pub enum ModuleType {
    UNUSED: (),
    ROUTING: (),
    AGGREGATION: (),
    LEGACY_MULTISIG: (),
    MERKLE_ROOT_MULTISIG: (),
    MESSAGE_ID_MULTISIG: (),
    NULL: (), // used with relayer carrying no metadata
    CCIP_READ: (),
    ARB_L2_TO_L1: (),
}

abi InterchainSecurityModule {
    #[storage(read)]
    fn verify(metadata: Bytes, message: Bytes) -> bool;

    // Returns an enum that represents the type of security model
    // encoded by this ISM. Relayers infer how to fetch and format metadata.
    fn module_type() -> ModuleType;
}
