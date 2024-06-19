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
    /// Verifies that the message is valid according to the ISM.
    /// /// /// ///
    /// /// ### Arguments
    /// ///
    /// /// * `metadata` - The metadata for ISM verification.
    /// /// * `message` - The message as emitted by dispatch.
    #[storage(read, write)]
    fn verify(metadata: Bytes, message: Bytes) -> bool;

    /// Returns an enum that represents the type of security model
    /// encoded by this ISM. Relayers infer how to fetch and format metadata.
    #[storage(read)]
    fn module_type() -> ModuleType;
}
