library;

/// Allows the beneficiary to claim the contract's balance.
abi Claimable {
    /// Gets the beneficiary.
    ///
    /// ### Returns
    ///
    /// * [Identity] - The beneficiary.
    #[storage(read)]
    fn beneficiary() -> Identity;

    /// Sets the beneficiary.
    ///
    /// ### Arguments
    ///
    /// * `beneficiary`: [Identity] - The beneficiary.
    #[storage(read, write)]
    fn set_beneficiary(beneficiary: Identity);

    /// Claims the contract's balance and sends it to the beneficiary.
    #[storage(read)]
    fn claim();
}

//  ----------------- Events -----------------

/// Logged when the benficiary is set.
pub struct BeneficiarySetEvent {
    pub beneficiary: b256,
}

/// Logged when the balance is claimed and sent to the beneficiary.
pub struct ClaimEvent {
    pub beneficiary: b256,
    pub amount: u64,
}
