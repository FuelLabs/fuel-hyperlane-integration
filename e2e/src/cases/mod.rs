mod example_test;
mod ism_test_something;
mod mailbox_get_domain;

mod asset_recieve;
mod asset_send;
mod message_receive;
mod message_send;

use std::{future::Future, pin::Pin};

pub struct TestCase {
    name: String,
    test: Box<dyn Fn() -> Pin<Box<dyn Future<Output = Result<f64, String>> + Send>> + Send>,
}

impl TestCase {
    pub fn new<F, Fut>(name: &str, test: F) -> Self
    where
        F: Fn() -> Fut + 'static + Send,
        Fut: Future<Output = Result<f64, String>> + 'static + Send,
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
        // ism_test_something::test(),
        // example_test::test(),
        //message_receive::test(), //Works
        //asset_recieve::test(), //Works

        // - igp hooka 0 gidiyor
        asset_send::test(),
        //message_send::test(), //Works but changes in IGP balance not changing
    ]
}
