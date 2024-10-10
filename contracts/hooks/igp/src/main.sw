contract;

use message::{EncodedMessage, Message};
use std::{bytes::Bytes, context::msg_amount,};
use interfaces::{igp::*, post_dispatch_hook::*};

storage {
    igp: ContractId = ContractId::zero(),
}

impl PostDispatchHookHelper for Contract {
    /// Initializes the IGP PostDispatchHook contract with the given contract ID.
    /// The contract ID is used to interact with the IGP contract.
    ///
    /// ### Arguments
    ///
    /// * `contract_id`: [ContractId] - The contract ID of the IGP contract.
    ///
    /// ### Reverts
    ///
    /// * If the contract is already initialized.
    #[storage(write)]
    fn initialize(contract_id: ContractId) {
        require(!_is_initialized(), IGPHookError::ContractAlreadyInitialized);
        storage.igp.write(contract_id)
    }
}

impl PostDispatchHook for Contract {
    /// Returns an enum that represents the type of hook
    ///
    /// ### Returns
    ///
    /// * [PostDispatchHookType] - The type of the hook.
    #[storage(read)]
    fn hook_type() -> PostDispatchHookType {
        PostDispatchHookType::INTERCHAIN_GAS_PAYMASTER
    }

    /// Returns whether the hook supports metadata
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata to be checked.
    ///
    /// ### Returns
    ///
    /// * [bool] - Whether the hook supports the metadata.
    #[storage(read)]
    fn supports_metadata(_metadata: Bytes) -> bool {
        false
    }

    /// Manages payments on a source chain to cover gas costs of relaying
    /// messages to destination chains and includes the gas overhead per destination
    ///
    /// The intended use of this contract is to store overhead gas amounts for destination
    /// domains, e.g. Mailbox and ISM gas usage, such that users of this IGP are only required
    /// to specify the gas amount used by their own applications.
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata required for the hook.
    /// * `message`: [Bytes] - The message being dispatched.
    ///
    /// ### Reverts
    ///
    /// * If the contract is not initialized.
    /// * If the message is invalid
    /// * If IGP call fails
    #[payable]
    #[storage(read, write)]
    fn post_dispatch(_metadata: Bytes, message: Bytes) {
        require(_is_initialized(), IGPHookError::ContractNotInitialized);

        let igp_contract = abi(IGP, storage.igp.read().bits());

        let message = EncodedMessage::from_bytes(message);
        let message_id = message.id();
        let destination_domain = message.destination();
        let sender = message.sender();
        let gas_amount = igp_contract.get_current_domain_gas();

        igp_contract
            .pay_for_gas {
                asset_id: b256::from(AssetId::base()),
                coins: msg_amount(),
            }(
                message_id,
                destination_domain,
                gas_amount,
                Identity::Address(Address::from(sender)),
            );
    }

    /// Compute the payment required by the postDispatch call
    ///
    /// ### Arguments
    ///
    /// * `metadata`: [Bytes] - The metadata required for the hook.
    /// * `message`: [Bytes] - The message being dispatched.
    ///
    /// ### Returns
    ///
    /// * [u64] - The payment required for the postDispatch call.
    ///
    /// ### Reverts
    ///
    /// * If the contract is not initialized.
    /// * If the message is invalid
    /// * If IGP call fails
    #[storage(read)]
    fn quote_dispatch(_metadata: Bytes, message: Bytes) -> u64 {
        require(_is_initialized(), IGPHookError::ContractNotInitialized);

        let igp_contract = abi(IGP, storage.igp.read().bits());
        let message = EncodedMessage::from_bytes(message);
        let domain = message.destination();

        let current_domain_gas = igp_contract.get_current_domain_gas();

        igp_contract.quote_gas_payment(domain, current_domain_gas)
    }
}

// ------------------------------------------------------------
// ------------------ Internal Functions ----------------------
// ------------------------------------------------------------

#[storage(read)]
fn _is_initialized() -> bool {
    storage.igp.read() != ContractId::zero()
}
