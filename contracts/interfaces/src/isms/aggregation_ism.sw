library;

use std::bytes::Bytes;

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
    /// * `owner`: [b256] - The address to be set as the owner of the contract.
    #[storage(read, write)]
    fn initialize(owner: b256);

    /// Sets the threshold for the Aggregation ISM.
    ///
    /// ### Arguments
    ///
    /// * `threshold`: [u8] - The threshold of approval for the Aggregation ISM.
    #[storage(write)]
    fn set_threshold(threshold: u8);

    /// Enrolls a module to the Aggregation ISM.
    ///
    /// ### Arguments
    ///
    /// * `module`: [ContractId] - The address of the module to be enrolled.
    #[storage(write)]
    fn enroll_module(module: ContractId);
}
