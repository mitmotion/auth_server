#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthToken {
    pub unique: u64,
}

impl AuthToken {
    pub fn generate() -> Self {
        Self {
            unique: rand::random(),
        }
    }

    pub fn serialize(&self) -> String {
        self.unique.to_string()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SignInResponse {
    pub token: AuthToken,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ValidityCheckResponse {
    pub player_uuid: Uuid,
}
