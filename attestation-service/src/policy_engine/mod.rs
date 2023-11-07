use anyhow::Result;
use as_types::SetPolicyInput;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod opa;

#[derive(Debug, EnumString, Deserialize)]
#[strum(ascii_case_insensitive)]
pub enum PolicyEngineType {
    OPA,
}

#[derive(Debug, EnumString, Deserialize, PartialEq)]
#[strum(ascii_case_insensitive)]
pub enum PolicyType {
    Rego,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyDigest {
    pub id: String,
    pub digest: String,
}

impl PolicyEngineType {
    #[allow(dead_code)]
    pub fn to_policy_engine(&self) -> Result<Box<dyn PolicyEngine + Send + Sync>> {
        match self {
            PolicyEngineType::OPA => {
                Ok(Box::new(opa::OPA::new()?) as Box<dyn PolicyEngine + Send + Sync>)
            }
        }
    }
}

#[async_trait]
pub trait PolicyEngine {
    async fn evaluate(
        &self,
        reference_data_map: HashMap<String, Vec<String>>,
        input: String,
        policy_id: Option<String>,
    ) -> Result<String>;

    async fn set_policy(&mut self, input: SetPolicyInput) -> Result<()>;

    async fn remove_policy(&mut self, policy_id: String) -> Result<()>;

    async fn list_policy(&self) -> Result<Vec<PolicyDigest>>;
}
