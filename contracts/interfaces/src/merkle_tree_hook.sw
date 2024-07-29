library;

abi MerkleTreeHook {
    #[storage(write)]
    fn initialize(mailbox: ContractId);

    #[storage(read)]
    fn count() -> u32;

    #[storage(read)]
    fn root() -> b256;

    #[storage(read)]
    fn latest_checkpoint() -> (b256, u32);
}

pub enum MerkleTreeEvent {
    InsertedIntoTree: (b256, u32),
}

pub enum MerkleTreeError {
    MessageNotDispatching: b256,
    NoValueExpected: (),
    ContractNotInitialized: (),
    ContractAlreadyInitialized: (),
}
