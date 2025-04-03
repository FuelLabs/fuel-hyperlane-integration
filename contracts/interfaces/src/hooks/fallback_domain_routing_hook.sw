library;

pub struct HookConfig {
    pub destination: u32,
    pub hook: b256,
}

abi FallbackDomainRoutingHook {
    /// Initializes the contract.
    ///
    /// ### Arguments
    ///
    /// * `owner`: [Identity] - The owner of the contract.
    /// * `fallback`: [b256] - The hook to fall back to if no hook is found.
    #[storage(write)]
    fn initialize(owner: Identity, fallback: b256);

    /// Sets the hook for a given destinationd domain.
    ///
    /// ### Arguments
    ///
    /// * `destination`: [u32] - The destination domain.
    /// * `hook`: [b256] - The hook to call for that domain.
    #[storage(read, write)]
    fn set_hook(destination: u32, hook: b256);

    /// Sets the hooks for multiple destination domains.
    ///
    /// ### Arguments
    ///
    /// * `hooks`: [Vec<HookConfig>] - The hooks to set.
    #[storage(read, write)]
    fn set_hooks(hooks: Vec<HookConfig>);


    /// Get contracts fallback hook
    ///
    /// ### Returns
    ///
    /// * [b256] - The Id of the fallback hook
    #[storage(read)]
    fn fallback_hook() -> b256;

    /// Get hook set for a domain
    ///
    /// ### Returns
    ///
    /// * [b256] - The Id of the hook set for a domain
    #[storage(read)]
    fn hooks(domain: u32) -> Option<b256>;
}