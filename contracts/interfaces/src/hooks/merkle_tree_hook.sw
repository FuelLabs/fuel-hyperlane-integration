library;

use merkle::MerkleTree;

abi MerkleTreeHook {
    /// Initializes the MerkleTree contract.
    ///
    /// ### Arguments
    ///
    /// * `mailbox`: [ContractId] - The contract ID of the Mailbox contract to initialize with.
    #[storage(write)]
    fn initialize(mailbox: ContractId);

    /// Gets the count of the MerkleTree library.
    ///
    /// ### Returns
    ///
    /// * [u32] - The count.
    #[storage(read)]
    fn count() -> u32;

    /// Gets the stored count of the MerkleTree library.
    /// And the current block number.
    /// Used since we cannot query point in time data.
    ///
    /// ### Returns
    ///
    /// * [(u32, u32)] - The count and the current block number.
    #[storage(read)]
    fn count_and_block() -> (u32, u32);

    /// Gets the root of the MerkleTree library.
    ///
    /// ### Returns
    ///
    /// * [b256] - The root.
    #[storage(read)]
    fn root() -> b256;

    /// Gets the latest checkpoint of the MerkleTree library.
    ///
    /// ### Returns
    ///
    /// * [b256] - The root.
    /// * [u32] - The count.
    #[storage(read)]
    fn latest_checkpoint() -> (b256, u32);

    #[storage(read)]
    fn tree() -> MerkleTree;
}

/// Merkle tree insertion event
pub struct InsertedIntoTreeEvent {
    pub message_id: b256,
    pub index: u32,
}

/// Errors that can occur while interacting with the MerkleTree contract.
pub enum MerkleTreeHookError {
    MessageNotDispatching: b256,
    NoValueExpected: (),
    ContractNotInitialized: (),
    ContractAlreadyInitialized: (),
    UnexpectedInitAddress: (),
    CannotInitializeWithZeroAddress: (),
}
