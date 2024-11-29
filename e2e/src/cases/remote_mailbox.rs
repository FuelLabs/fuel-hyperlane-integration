use crate::{
    cases::TestCase,
    evm::{get_evm_metadata_from_yaml, get_evm_wallet, SepoliaContracts},
};
use tokio::time::Instant;

async fn remote_mailbox_test() -> Result<f64, String> {
    let start: Instant = Instant::now();

    let wallet = get_evm_wallet().await;
    let contracts = SepoliaContracts::initialize(wallet.clone()).await;
    let mailbox = contracts.mailbox;

    let owner = mailbox.owner().call().await.unwrap()._0;
    if owner != wallet.default_signer().address() {
        return Err("Mailbox not owned by wallet".to_string());
    }

    let expected_domain = get_evm_metadata_from_yaml().domainId;
    let local_domain = mailbox.localDomain().call().await.unwrap()._0;

    if local_domain.to_string() != expected_domain {
        return Err(format!(
            "Domain mismatch. Expected: {}, Got: {}",
            expected_domain, local_domain
        ));
    }

    Ok(start.elapsed().as_secs_f64())
}

pub fn test() -> TestCase {
    TestCase::new("remote_mailbox_test", remote_mailbox_test)
}
