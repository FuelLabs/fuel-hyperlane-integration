library;

pub enum DomainRoutingIsmError {
    DomainModuleLengthMismatch: (u64, u64),
    DomainNotSet: u32,
}

abi DomainRoutingIsm {
    /// Sets the ISMs to be used for the specified origin domains
    ///
    /// ### Arguments
    ///
    /// * `owner`: [Identity] - The address of the owner.
    /// * `domains`: [Vec<u32>] - The list of origin domains.
    /// * `modules`: [Vec<b256>] - The list of ISMs to be used for the specified domains.
    #[storage(write, read)]
    fn initialize_with_domains(owner: Identity, domains: Vec<u32>, modules: Vec<b256>);

    /// Sets the ISM to be used for the specified origin domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The origin domain.
    /// * `module`: [b256] - The ISM to be used for the specified domain.
    #[storage(write, read)]
    fn set(domain: u32, module: b256);

    /// Removes the specified origin domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The origin domain.
    #[storage(write, read)]
    fn remove(domain: u32);

    /// Returns the domains that have been set
    ///
    /// ### Returns
    ///
    /// * [Vec<u32>] - The list of origin domains.
    #[storage(read)]
    fn domains() -> Vec<u32>;

    /// Returns the ISM to be used for the specified origin domain
    ///
    /// ### Arguments
    ///
    /// * `domain`: [u32] - The origin domain.
    ///
    /// ### Returns
    ///
    /// * [b256] - The ISM to be used for the specified domain.
    #[storage(read)]
    fn module(domain: u32) -> b256;
}
