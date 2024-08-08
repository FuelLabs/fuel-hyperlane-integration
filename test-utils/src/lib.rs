use std::str::FromStr;

//use ethers::core::k256::ecdsa::SigningKey;
use ethers::types::{Signature as EthersSignature, U256};
//use ethers_signers::{LocalWallet, Signer, Wallet};

use fuels::{
    accounts::{wallet::WalletUnlocked, Account},
    crypto::SecretKey,
    tx::Receipt,
    types::{
        bech32::Bech32Address, errors::transaction::Reason, errors::Error, transaction::TxPolicies,
        AssetId, Bits256, EvmAddress, B512,
    },
};
use hyperlane_core::{
    HyperlaneSigner, HyperlaneSignerExt, Signable, Signature as HyperlaneSignature, H256,
};
use hyperlane_ethereum::Signers;
use serde::{de::Deserializer, Deserialize};

fn hyperlane_to_ethers_u256(value: hyperlane_core::U256) -> ethers::types::U256 {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    ethers::types::U256::from_big_endian(&bytes)
}

pub struct HyperlaneSignatureWrapper(HyperlaneSignature);

impl From<HyperlaneSignature> for HyperlaneSignatureWrapper {
    fn from(sig: HyperlaneSignature) -> Self {
        HyperlaneSignatureWrapper(sig)
    }
}

impl From<HyperlaneSignatureWrapper> for EthersSignature {
    fn from(val: HyperlaneSignatureWrapper) -> Self {
        EthersSignature {
            r: hyperlane_to_ethers_u256(val.0.r),
            s: hyperlane_to_ethers_u256(val.0.s),
            v: val.0.v,
        }
    }
}

pub fn h256_to_bits256(h: H256) -> Bits256 {
    Bits256(h.0)
}

pub fn bits256_to_h256(b: Bits256) -> H256 {
    H256(b.0)
}

pub fn evm_address(signer: &Signers) -> EvmAddress {
    h256_to_bits256(signer.eth_address().into()).into()
}

pub fn zero_address() -> EvmAddress {
    EvmAddress::from(Bits256([0u8; 32]))
}

/*
pub fn get_signer(private_key: &str) -> Signers {
    let wallet: LocalWallet = private_key.parse().unwrap();
    Signers::from(wallet)
}
*/

pub fn signature_to_compact(signature: &EthersSignature) -> [u8; 64] {
    let mut compact = [0u8; 64];

    let mut r_bytes = [0u8; 32];
    signature.r.to_big_endian(&mut r_bytes);

    let mut s_and_y_parity_bytes = [0u8; 32];
    // v is either 27 or 28, subtract 27 to normalize to y parity as 0 or 1
    let y_parity = signature.v - 27;
    let s_and_y_parity = (U256::from(y_parity) << 255) | signature.s;
    s_and_y_parity.to_big_endian(&mut s_and_y_parity_bytes);

    compact[..32].copy_from_slice(&r_bytes);
    compact[32..64].copy_from_slice(&s_and_y_parity_bytes);

    compact
}

pub async fn sign_compact<T: Signable + std::marker::Send>(signer: &Signers, signable: T) -> B512 {
    let signed = signer.sign(signable).await.unwrap();
    let ethers_signature: EthersSignature =
        HyperlaneSignatureWrapper::from(signed.signature).into();
    return B512::try_from(signature_to_compact(&ethers_signature).as_slice()).unwrap();
}

pub async fn funded_wallet_with_private_key(
    funder: &WalletUnlocked,
    private_key: &str,
) -> WalletUnlocked {
    let secret_key = SecretKey::from_str(private_key).unwrap();
    let provider = funder.provider().unwrap().clone();
    let wallet = WalletUnlocked::new_from_private_key(secret_key, Some(provider));

    fund_address(funder, wallet.address()).await.unwrap();
    wallet
}

async fn fund_address(from_wallet: &WalletUnlocked, to: &Bech32Address) -> Result<(), Error> {
    // Only a balance of 1 is required to be able to sign transactions from an Address.
    let amount: u64 = 1;
    from_wallet
        .transfer(to, amount, AssetId::BASE, TxPolicies::default())
        .await?;

    Ok(())
}

pub fn get_revert_reason(call_error: Error) -> String {
    if let Error::Transaction(Reason::Reverted { reason, .. }) = call_error {
        reason
    } else {
        panic!(
            "Error is not a RevertTransactionError. Error: {:?}",
            call_error
        );
    }
}

// Given an Error from a call or simulation, returns the revert reason.
// Panics if it's unable to find the revert reason.
pub fn get_revert_string(call_error: Error) -> String {
    let receipts = if let Error::Transaction(Reason::Reverted { receipts, .. }) = call_error {
        receipts
    } else {
        panic!(
            "Error is not a RevertTransactionError. Error: {:?}",
            call_error
        );
    };

    // The receipts will be:
    // [any prior receipts..., LogData with reason, Revert, ScriptResult]
    // We want the LogData with the reason, which is utf-8 encoded as the `data`.

    let revert_reason_receipt = &receipts[receipts.len() - 3];
    let data = if let Receipt::LogData { data, .. } = revert_reason_receipt {
        data
    } else {
        panic!(
            "Expected LogData receipt. Receipt: {:?}",
            revert_reason_receipt
        );
    };

    let data: Vec<u8> = data
        .as_ref()
        .unwrap()
        .iter()
        .cloned()
        .filter(|&byte| byte != 0)
        .collect();
    String::from_utf8(data).unwrap()
}

/// Kludge to deserialize into Bits256
pub fn deserialize_bits_256<'de, D>(deserializer: D) -> Result<Bits256, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(deserializer)?;

    Bits256::from_hex_str(&buf).map_err(serde::de::Error::custom)
}

/// Kludge to deserialize into Vec<Bits256>
pub fn deserialize_vec_bits_256<'de, D>(deserializer: D) -> Result<Vec<Bits256>, D::Error>
where
    D: Deserializer<'de>,
{
    let strs = Vec::<String>::deserialize(deserializer)?;

    let mut vec = Vec::with_capacity(strs.len());

    for s in strs.iter() {
        vec.push(Bits256::from_hex_str(s).map_err(serde::de::Error::custom)?);
    }

    Ok(vec)
}

/// Encodes a MultisigMetadata struct into a Vec<u8>
/// with the format expected by the Sway contracts.
pub fn encode_multisig_metadata(
    root: &H256,
    index: u32,
    mailbox: &H256,
    proof: &Vec<H256>,
    signatures: &Vec<B512>,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&root.0);
    bytes.extend_from_slice(&index.to_be_bytes());
    bytes.extend_from_slice(&mailbox.0);
    for proof in proof {
        bytes.extend_from_slice(&proof.0);
    }
    for signature in signatures {
        for b256 in signature.bytes.iter() {
            bytes.extend_from_slice(&b256.0);
        }
    }
    bytes
}
