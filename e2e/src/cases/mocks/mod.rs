mod asset_receive;
mod asset_send;
mod message_receive;
mod message_send;

use std::{future::Future, pin::Pin, sync::Arc};

use crate::utils::contract_registry::ContractRegistry;

pub struct TestCase {
    name: String,
    test: Box<
        dyn Fn(Arc<ContractRegistry>) -> Pin<Box<dyn Future<Output = Result<f64, String>> + Send>>
            + Send,
    >,
}

impl TestCase {
    pub fn new<F, Fut>(name: &str, test: F) -> Self
    where
        F: Fn(Arc<ContractRegistry>) -> Fut + 'static + Send,
        Fut: Future<Output = Result<f64, String>> + 'static + Send,
    {
        Self {
            name: name.to_string(),
            test: Box::new(move |registry| Box::pin(test(registry))),
        }
    }

    pub async fn run(self, registry: Arc<ContractRegistry>) -> Result<f64, String> {
        (self.test)(registry).await
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
        // mock_asset_send::test(),
        // mock_asset_recieve::test(),
        // mock_message_send::test(),
        // mock_message_receive::test(), //Works
    ]
}
