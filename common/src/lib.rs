#![forbid(unsafe_code)]

use serde::{Serialize, Deserialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthToken {
    unique: u128,
}

impl AuthToken {
    pub fn generate() -> Self {
        Self {
            unique: rand::random(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SignInData {
    pub token: AuthToken,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ValidityCheckData {
    pub player_uuid: Uuid,
}
