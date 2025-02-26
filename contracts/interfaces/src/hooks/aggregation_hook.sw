library;

abi AggregationHook {
    /// Initializes the AggregationHook contract.
    ///
    /// ### Arguments
    ///
    /// * `hooks`: [Vec<ContractId>] - The hooks to initialize with.
    #[storage(write, read)]
    fn initialize(hooks: Vec<ContractId>);

    /// Gets the hooks.
    ///
    /// ### Returns
    ///
    /// * [Vec<ContractId>] - The hooks.
    ///
    /// ### Reverts
    ///
    /// * If the contract is not initialized.
    #[storage(read)]
    fn get_hooks() -> Vec<ContractId>;
}

pub enum AggregationHookError {
    UnexpectedInitAddress: (),
    AlreadyInitialized: (),
}