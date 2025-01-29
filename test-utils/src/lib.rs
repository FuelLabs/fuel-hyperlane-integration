use std::{fs::File, io::Read, str::FromStr};

//use ethers::core::k256::ecdsa::SigningKey;
use ethers::{
    types::{Signature as EthersSignature, U256},
    // utils::hex::serde,
};
//use ethers_signers::{LocalWallet, Signer, Wallet};

use ::serde::{de::Error as SerdeError, Deserialize, Deserializer};
use fuels::{
    accounts::{wallet::WalletUnlocked, Account},
    crypto::SecretKey,
    types::{
        bech32::Bech32Address, errors::transaction::Reason, errors::Error, transaction::TxPolicies,
        AssetId, Bits256, EvmAddress, B512,
    },
};
use hyperlane_core::{
    HyperlaneMessage, RawHyperlaneMessage, Signature as HyperlaneSignature, H256,
};
// use hyperlane_ethereum::Signers;

fn hyperlane_to_ethers_u256(value: hyperlane_core::U256) -> ethers::types::U256 {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    ethers::types::U256::from_big_endian(&bytes)
}

pub struct Announcement {
    pub validator: EvmAddress,
    pub mailbox_address: H256,
    pub mailbox_domain: u32,
    pub storage_location: String,
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

// pub fn evm_address(signer: &Signers) -> EvmAddress {
//     h256_to_bits256(signer.eth_address().into()).into()
// }

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

// pub async fn sign_compact<T: Signable + std::marker::Send>(signer: &Signers, signable: T) -> B512 {
//     let signed = signer.sign(signable).await.unwrap();
//     let ethers_signature: EthersSignature =
//         HyperlaneSignatureWrapper::from(signed.signature).into();
//     return B512::try_from(signature_to_compact(&ethers_signature).as_slice()).unwrap();
// }

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

/// Kludge to deserialize into Bits256
pub fn deserialize_bits_256<'de, D>(deserializer: D) -> Result<Bits256, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(deserializer)?;

    Bits256::from_hex_str(&buf).map_err(SerdeError::custom)
}

pub fn deserialize_hyperlane_message<'de, D>(deserializer: D) -> Result<HyperlaneMessage, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(deserializer)?;
    let raw_message: RawHyperlaneMessage = buf.as_bytes().to_vec();

    Ok(HyperlaneMessage::from(raw_message))
}

/// Kludge to deserialize into Vec<Bits256>
pub fn deserialize_vec_bits_256<'de, D>(deserializer: D) -> Result<Vec<Bits256>, D::Error>
where
    D: Deserializer<'de>,
{
    let strs = Vec::<String>::deserialize(deserializer)?;

    let mut vec = Vec::with_capacity(strs.len());

    for s in strs.iter() {
        vec.push(Bits256::from_hex_str(s).map_err(SerdeError::custom)?);
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

// ----------------------------------------------------------------------------
// Merkle Related Utils

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MerkleProof {
    #[serde(deserialize_with = "deserialize_bits_256")]
    pub leaf: Bits256,
    pub index: u32,
    #[serde(deserialize_with = "deserialize_vec_bits_256")]
    pub path: Vec<Bits256>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MerkleTestCase {
    #[allow(dead_code)]
    pub test_name: String,
    #[serde(deserialize_with = "deserialize_bits_256")]
    pub expected_root: Bits256,
    pub leaves: Vec<String>,
    pub proofs: Vec<MerkleProof>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MerkleRootIsmTestCase {
    #[serde(deserialize_with = "deserialize_bits_256")]
    pub leaf: Bits256,
    pub index: u32,
    #[serde(deserialize_with = "deserialize_vec_bits_256")]
    pub proof: Vec<Bits256>,
    #[serde(deserialize_with = "deserialize_hyperlane_message")]
    pub message: HyperlaneMessage,
    #[serde(deserialize_with = "deserialize_bits_256")]
    pub root: Bits256,
}

/// Reads merkle test case json file and returns a vector of `TestCase`s
/// The test case is taken from https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/vectors/merkle.json
pub fn get_merkle_test_cases(path: &str) -> Vec<MerkleTestCase> {
    let mut file = File::open(path).unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();
    serde_json::from_str(&data).unwrap()
}

/// See https://eips.ethereum.org/EIPS/eip-191
/// This is required because the leaf strings in the merkle test cases
/// are hashed using ethers.utils.hashMessage (https://eips.ethereum.org/EIPS/eip-191)
pub fn to_eip_191_payload(message: &str) -> String {
    format!(
        "\x19Ethereum Signed Message:\n{:}{:}",
        message.len(),
        message
    )
}

pub fn get_eip_191_prefix_for_hashes() -> &'static str {
    // same as format!("\x19Ethereum Signed Message:\n32")
    "19457468657265756d205369676e6564204d6573736167653a0a3332"
}

/// Reads merkle root ism test case json file and returns `TestCase` with the required data
/// The test case is taken from https://github.com/hyperlane-xyz/hyperlane-monorepo/blob/main/vectors/messageWithProof.json
pub fn get_merkle_root_ism_test_data(path: &str) -> MerkleRootIsmTestCase {
    let mut file = File::open(path).unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();
    serde_json::from_str(&data).unwrap()
}
// ----------------------------------------------------------------------------
