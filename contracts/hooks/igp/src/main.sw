contract;

use message::{EncodedMessage, Message};
use std::{bytes::Bytes, context::msg_amount,};
use interfaces::{igp::*, post_dispatch_hook::*};

storage {
    igp: ContractId = ContractId::zero(),
}

impl PostDispatchHookHelper for Contract {
    #[storage(write)]
    fn initialize(contract_id: ContractId) {
        require(!_is_initialized(), IGPHookError::ContractAlreadyInitialized);
        storage.igp.write(contract_id)
    }
}

impl PostDispatchHook for Contract {
    #[storage(read)]
    fn hook_type() -> PostDispatchHookType {
        PostDispatchHookType::INTERCHAIN_GAS_PAYMASTER
    }

    #[storage(read)]
    fn supports_metadata(_metadata: Bytes) -> bool {
        false
    }

    /**
    * @title InterchainGasPaymaster
    * @notice Manages payments on a source chain to cover gas costs of relaying
    * messages to destination chains and includes the gas overhead per destination
    * @dev The intended use of this contract is to store overhead gas amounts for destination
    * domains, e.g. Mailbox and ISM gas usage, such that users of this IGP are only required
    * to specify the gas amount used by their own applications.
    */
    #[payable]
    #[storage(read, write)]
    fn post_dispatch(_metadata: Bytes, message: Bytes) {
        require(msg_amount() == 0, IGPHookError::NoValueExpected);
        require(_is_initialized(), IGPHookError::ContractNotInitialized);

        let igp_contract = abi(IGP, storage.igp.read().bits());

        let message = EncodedMessage::from_bytes(message);
        let message_id = message.id();
        let destination_domain = message.destination();
        let sender = message.sender();
        let gas_amount = 1000; //Todo: Must be changed to DEFAULT_GAS_VALUE
        igp_contract.pay_for_gas(
            message_id,
            destination_domain,
            gas_amount,
            Identity::Address(Address::from(sender)),
        );
    }

    /**
    * @notice Quote dispatch hook implementation.
    * @param metadata The metadata of the message being dispatched.
    * @param message The message being dispatched.
    * @return The quote for the dispatch.
    */
    #[storage(read)]
    fn quote_dispatch(_metadata: Bytes, message: Bytes) -> u64 {
        require(_is_initialized(), IGPHookError::ContractNotInitialized);

        let igp_contract = abi(IGP, storage.igp.read().bits());
        let message = EncodedMessage::from_bytes(message);
        let domain = message.destination();

        igp_contract.quote_gas_payment(domain, 1000)
    }
}

#[storage(read)]
fn _is_initialized() -> bool {
    storage.igp.read() != ContractId::zero()
}
