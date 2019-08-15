use sha3::{Digest, Sha3_512};
use serde::{Deserialize, Serialize};
use crate::util::{Result, wrap_err};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
struct HashEntry {
    hash: HashData,
    salt: Salt,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
struct HashData {
    output: Vec<u8>,
}

impl HashData {
    fn new(v: &[u8], salt: Salt) -> Self {
        let mut hasher = Sha3_512::new();
        hasher.input(salt.unique.to_le_bytes());
        hasher.input(v);
        let result = hasher.result();
        Self {
            output: result[..].to_vec(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
struct Salt {
    unique: u128,
}

impl Salt {
    fn new() -> Self {
        Self {
            unique: rand::random(),
        }
    }
}

pub fn hash(v: impl AsRef<[u8]>) -> Result<String> {
    let salt = Salt::new();
    let hash = HashData::new(v.as_ref(), salt);
    let entry = HashEntry {
        hash,
        salt,
    };
    wrap_err(serde_json::to_string(&entry))
}

pub fn verify(v: impl AsRef<[u8]>, hash: &str) -> Result<bool> {
    let hashentry: HashEntry = wrap_err(serde_json::from_str(hash))?;
    let chash = HashData::new(v.as_ref(), hashentry.salt);
    Ok(chash == hashentry.hash)
}
