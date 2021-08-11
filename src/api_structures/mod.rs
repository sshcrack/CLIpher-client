use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionKey {
    pub public_key: String,
    pub expires_at: serde_json::Number
}