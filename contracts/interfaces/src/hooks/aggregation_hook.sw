library;

abi AggregationHook {
    /// Initializes the AggregationHook contract.
    ///
    /// ### Arguments
    ///
    /// * `owner`: [b256] - The owner of the contract.
    /// * `hooks`: [Vec<ContractId>] - The hooks to initialize with.
    ///
    /// ### Reverts
    ///
    /// * If the contract is already initialized.
    #[storage( write)]
    fn initialize(owner: b256, hooks: Vec<ContractId>);


    /// Adds a hook to the contract.
    ///
    /// ### Arguments
    ///
    /// * `hook`: [ContractId] - The hook to add.
    ///
    /// ### Reverts
    ///
    /// * If the hook already exists.
    #[storage(read, write)]
    fn add_hook(hook: ContractId);

    /// Removes a hook from the contract.
    ///
    /// ### Arguments
    ///
    /// * `hook`: [ContractId] - The hook to remove.
    ///
    /// ### Reverts
    ///
    /// * If the hook does not exist.
    #[storage(read, write)]
    fn remove_hook(hook: ContractId);

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

/// Errors that can occur in the AggregationHook contract.
pub enum AggregationHookError {
    /// The contract is already initialized.
    ContractAlreadyInitialized: (),
    /// The contract is not initialized.
    ContractNotInitialized: (),
    /// The hook already exists.
    HookAlreadyExists: (),
    /// The hook was not found.
    HookNotFound: (),
    /// No hooks configured.
    NoHooksConfigured: (),
    /// Incorrect total hook payment.
    IncorrectTotalHookPayment: (),
    /// Hook cannot be removed.
    HookCannotBeRemoved: (),
}
