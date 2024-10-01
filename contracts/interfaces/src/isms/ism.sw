library;

use std::bytes::Bytes;

/// Enum representing the type of Interchain Security Module.
pub enum ModuleType {
    UNUSED: (),
    ROUTING: (),
    AGGREGATION: (),
    LEGACY_MULTISIG: (),
    MERKLE_ROOT_MULTISIG: (),
    MESSAGE_ID_MULTISIG: (),
    NULL: (), // used with relayer carrying no metadata
    CCIP_READ: (),
}

/// Official ISM interface for Hyperlane V3
abi InterchainSecurityModule {
    /// Verifies the message using the metadata.
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata to be used for verification.
    /// * `message`: [Bytes] - The message to be verified.
    ///
    /// ### Returns
    ///
    /// * [bool] - True if the message is verified successfully.
    #[storage(read)]
    fn verify(metadata: Bytes, message: Bytes) -> bool;

    /// Returns an enum that represents the type of security model
    /// encoded by this ISM. Relayers infer how to fetch and format metadata.
    ///
    /// ### Returns
    ///
    /// * [ModuleType] - The type of security model.
    fn module_type() -> ModuleType;
}
