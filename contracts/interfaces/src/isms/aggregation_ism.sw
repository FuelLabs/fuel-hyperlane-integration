library;

use std::bytes::Bytes;

pub enum AggregationIsmError {
    DidNotMeetThreshold: (),
    UnexpectedInitAddress: (),
    FailedToVerify: (),
    AlreadyInitialized: (),
}


///  Official Aggregation ISM interface for Hyperlane V3
abi AggregationIsm {
    /// Returns the modules and threshold for the Aggregation ISM for the given message.
    ///
    /// ### Arguments
    ///
    /// * `message`: [Bytes] - The message to be processed.
    ///
    /// ### Returns
    ///
    /// * [Vec<ContractId>] - The list of modules to be used for message verification.
    /// * [u8] - The threshold of approval for the Aggregation ISM.
    #[storage(read)]
    fn modules_and_threshold(message: Bytes) -> (Vec<ContractId>, u8);
}

///  Additional functions added for the fully functional implementation of the Aggregation ISM
abi AggregationIsmFunctions {
    /// Initializes the contract.
    ///
    /// ### Arguments
    ///
    /// * `modules`: [Vec<ContractId>] - The list of modules to be used for message verification.
    /// * `threshold`: [u8] - The threshold of approval for the Aggregation ISM.
    #[storage(read, write)]
    fn initialize(modules: Vec<ContractId>, threshold: u8);
}
