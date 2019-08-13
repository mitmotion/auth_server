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

    pub fn deserialize(s: &str) -> Self {
        let n = s.parse().unwrap();
        Self { unique: n }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SignInResponse {
    pub token: AuthToken,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ValidityCheckResponse {
    pub uuid: Uuid,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct UuidLookupResponse {
    pub uuid: Uuid,
}
