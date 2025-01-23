library;

/// All other functions for the PausableHook Hyperlane interface are inherited through the Pausable abi.
/// Source: [sway-libs](https://github.com/FuelLabs/sway-libs/blob/master/libs/src/pausable.sw)
abi PausableHook {
    /// Initializes the contract.
    ///
    /// ### Arguments
    ///
    /// * `owner`: [Identity] - The owner of the contract.
    #[storage(write)]
    fn initialize(owner: Identity);
}
