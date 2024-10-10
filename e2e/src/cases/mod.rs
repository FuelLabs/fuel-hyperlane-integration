mod collateral_asset_send;
mod ism_test_something;
mod mailbox_config;
mod message_send;
mod message_send_with_gas;
mod set_gas_configs;

use std::{future::Future, pin::Pin};
pub struct TestCase {
    name: String,
    test: Box<dyn Fn() -> Pin<Box<dyn Future<Output = Result<f64, String>>>>>,
}

impl TestCase {
    pub fn new<F, Fut>(name: &str, test: F) -> Self
    where
        F: Fn() -> Fut + 'static,
        Fut: Future<Output = Result<f64, String>> + 'static,
    {
        Self {
            name: name.to_string(),
            test: Box::new(move || Box::pin(test())),
        }
    }

    pub async fn run(self) -> Result<f64, String> {
        (self.test)().await
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }
}

pub struct FailedTestCase {
    name: String,
    error: String,
}

impl FailedTestCase {
    pub fn new(name: String, error: String) -> Self {
        Self { name, error }
    }

    pub fn log(&self) {
        println!("Test {} failed: {}", self.name, self.error);
    }
}

pub fn pull_test_cases() -> Vec<TestCase> {
    vec![
        mailbox_config::test(),
        set_gas_configs::test(),
        message_send::test(),
        message_send_with_gas::test(),
        collateral_asset_send::test(),
        // ism_test_something::test(),
    ]
}
