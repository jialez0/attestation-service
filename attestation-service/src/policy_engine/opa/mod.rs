use crate::policy_engine::{PolicyDigest, PolicyEngine, PolicyType};
use anyhow::{anyhow, bail, Result};
use as_types::SetPolicyInput;
use async_trait::async_trait;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha384};
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::str::FromStr;

// Link import cgo function
#[link(name = "cgo")]
extern "C" {
    pub fn evaluateGo(policy: GoString, data: GoString, input: GoString) -> *mut c_char;
}

/// String structure passed into cgo
#[derive(Debug)]
#[repr(C)]
pub struct GoString {
    pub p: *const c_char,
    pub n: isize,
}

type PolicyMap = HashMap<String, String>;

#[derive(Debug)]
pub struct OPA {
    policy_map: PolicyMap,
}

impl OPA {
    pub fn new() -> Result<Self> {
        let default_policy = std::include_str!("default_policy.rego");
        let mut policy_map = HashMap::new();
        policy_map.insert("default".to_string(), default_policy.to_string());

        Ok(Self { policy_map })
    }
}

#[async_trait]
impl PolicyEngine for OPA {
    async fn evaluate(
        &self,
        reference_data_map: HashMap<String, Vec<String>>,
        input: String,
        policy_id: Option<String>,
    ) -> Result<String> {
        let policy = self
            .policy_map
            .get(&policy_id.unwrap_or("default".to_string()))
            .ok_or_else(|| anyhow!("Invalid Policy ID"))?;

        let policy_go = GoString {
            p: policy.as_ptr() as *const c_char,
            n: policy.len() as isize,
        };

        let reference = serde_json::json!({ "reference": reference_data_map }).to_string();

        let reference_go = GoString {
            p: reference.as_ptr() as *const c_char,
            n: reference.len() as isize,
        };

        let input_go = GoString {
            p: input.as_ptr() as *const c_char,
            n: input.len() as isize,
        };

        // Call the function exported by cgo and process the returned decision
        let decision_buf: *mut c_char = unsafe { evaluateGo(policy_go, reference_go, input_go) };
        let decision_str: &CStr = unsafe { CStr::from_ptr(decision_buf) };
        let res = decision_str.to_str()?.to_string();
        debug!("Evaluated: {}", res);
        if res.starts_with("Error::") {
            return Err(anyhow!(res));
        }

        // If a clear approval opinion is given in the evaluation report,
        // the rejection information will be reflected in the evaluation failure return value.
        let res_kv: Value = serde_json::from_str(&res)?;
        if let Some(allow) = res_kv["allow"].as_bool() {
            if !allow {
                bail!("Untrusted TEE evidence")
            }
        }

        Ok(res)
    }

    async fn set_policy(&mut self, input: SetPolicyInput) -> Result<()> {
        let policy_type = PolicyType::from_str(&input.r#type)
            .map_err(|_| anyhow!("{} is not support by AS", &input.r#type))?;
        if policy_type != PolicyType::Rego {
            bail!("OPA Policy Engine only support .rego policy");
        }

        let policy_bytes = base64::engine::general_purpose::STANDARD
            .decode(input.policy)
            .map_err(|e| anyhow!("Base64 decode OPA policy string failed: {:?}", e))?;

        self.policy_map.insert(
            input.policy_id,
            String::from_utf8(policy_bytes)
                .map_err(|_| anyhow!("Illegal policy content string"))?,
        );

        Ok(())
    }

    async fn remove_policy(&mut self, policy_id: String) -> Result<()> {
        self.policy_map.remove(&policy_id);
        Ok(())
    }

    async fn list_policy(&self) -> Result<Vec<PolicyDigest>> {
        let mut policy_list = Vec::new();

        for (id, policy) in &self.policy_map {
            let mut hasher = Sha384::new();
            hasher.update(&policy);
            let digest = hasher.finalize().to_vec();
            policy_list.push(PolicyDigest {
                id: id.to_string(),
                digest: base64::engine::general_purpose::STANDARD.encode(digest),
            });
        }

        Ok(policy_list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn dummy_reference(ver: u64) -> String {
        json!({
            "productId": [ver.to_string()],
            "svn": [ver.to_string()]
        })
        .to_string()
    }

    fn dummy_input(product_id: u64, svn: u64) -> String {
        json!({
            "productId": product_id.to_string(),
            "svn": svn.to_string()
        })
        .to_string()
    }

    #[tokio::test]
    async fn test_evaluate() {
        let default_policy_id = "default".to_string();

        let opa = OPA::new().unwrap();

        let reference_data: HashMap<String, Vec<String>> =
            serde_json::from_str(&dummy_reference(5)).unwrap();

        let res = opa
            .evaluate(
                reference_data.clone(),
                dummy_input(5, 5),
                Some(default_policy_id.clone()),
            )
            .await;
        assert!(res.is_ok(), "OPA execution() should be success");

        let res = opa
            .evaluate(reference_data, dummy_input(0, 0), Some(default_policy_id))
            .await;
        assert!(res.is_err(), "OPA execution() should be failed");
    }

    #[tokio::test]
    async fn test_set_policy() {
        let mut opa = OPA::new().unwrap();
        let policy = "package policy
default allow = true"
            .to_string();

        let input = SetPolicyInput {
            r#type: "rego".to_string(),
            policy_id: "test".to_string(),
            policy: base64::engine::general_purpose::STANDARD.encode(policy),
        };

        assert!(opa.set_policy(input).await.is_ok());
    }
}
