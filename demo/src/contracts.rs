use std::str::FromStr;

use fuels::{
    accounts::wallet::WalletUnlocked,
    macros::abigen,
    types::{Bits256, Bytes, ContractId},
};

use crate::helper::{get_contract_id_from_json, get_value_from_json};

abigen!(
    Contract(
        name = "Mailbox",
        abi = "contracts/mailbox/out/debug/mailbox-abi.json",
    ),
    Contract(
        name = "PostDispatch",
        abi = "contracts/mocks/mock-post-dispatch/out/debug/mock-post-dispatch-abi.json",
    ),
    Contract(
        name = "MerkleTreeHook",
        abi = "contracts/hooks/merkle-tree-hook/out/debug/merkle-tree-hook-abi.json",
    ),
    Contract(
        name = "IGPHook",
        abi = "contracts/hooks/igp/out/debug/igp-hook-abi.json",
    ),
    Contract(
        name = "ValidatorAnnounce",
        abi = "contracts/validator-announce/out/debug/validator-announce-abi.json",
    ),
);

pub struct SepoliaContracts {
    pub mailbox: String,
    pub recipient: String,
}

pub struct FuelContracts {
    pub mailbox: Mailbox<WalletUnlocked>,
    pub igp: ContractId,
    pub ism: ContractId,
    pub merkle_tree_hook: ContractId,
    pub validator_announce: ContractId,
}

pub struct Contracts {
    pub fuel: FuelContracts,
    pub sepolia: SepoliaContracts,
}

impl Contracts {
    pub async fn fuel_send_dispatch(&self) {
        let recipient_address = hex::decode("c2E0b1526E677EA0a856Ec6F50E708502F7fefa9").unwrap();
        let mut address_array = [0u8; 32];
        address_array[12..].copy_from_slice(&recipient_address);

        let body = hex::encode("Hello from Fuel!").into_bytes();
        let res = self
            .fuel
            .mailbox
            .methods()
            .dispatch(
                11155111,
                Bits256(address_array),
                Bytes(body),
                Bytes(vec![0]),
                ContractId::zeroed(),
            )
            .determine_missing_contracts(Some(3))
            .await
            .unwrap()
            .call()
            .await;

        if let Err(e) = res {
            println!("Dispatch error: {:?}", e);
        } else {
            println!("Dispatch Success!");
        }
    }
}

pub fn load_contracts(wallet: WalletUnlocked) -> Contracts {
    let mailbox_id =
        ContractId::from_str("0xb8401ae1ffd5d6d719bc5496cd5016761a1f3ac0c363a3762cab84edd5286625")
            .unwrap();

    // fuel contract addresses
    //let mailbox_id = get_value_from_json("fueltestnet", &["mailbox"]);
    let igp = get_contract_id_from_json("fueltestnet", &["interchainGasPaymaster"]);
    let ism = get_contract_id_from_json("fueltestnet", &["interchainSecurityModule"]);
    let merkle_tree_hook = get_contract_id_from_json("fueltestnet", &["merkleTreeHook"]);
    let validator_announce = get_contract_id_from_json("fueltestnet", &["validatorAnnounce"]);

    // sepolia contract addresses
    let recipient = get_value_from_json("sepolia", &["testRecipient"]);
    let sepolia_mailbox = get_value_from_json("sepolia", &["mailbox"]);

    let mailbox_instance = Mailbox::new(
        ContractId::from_str(&mailbox_id.to_string()).unwrap(),
        wallet.clone(),
    );

    Contracts {
        fuel: FuelContracts {
            mailbox: mailbox_instance,
            igp,
            ism,
            merkle_tree_hook,
            validator_announce,
        },
        sepolia: SepoliaContracts {
            mailbox: sepolia_mailbox.to_string(),
            recipient: recipient.to_string(),
        },
    }
}
