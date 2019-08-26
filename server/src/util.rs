use argon2::{Config, ThreadMode, Variant, Version};
use failure::Error;
use rand::prelude::*;
use std::error::Error as StdError;
use std::result::Result as StdResult;

pub type Result<T> = StdResult<T, Error>;

pub fn wrap_err<T, E: 'static + StdError + Sync + Send>(r: StdResult<T, E>) -> Result<T> {
    r.map_err(|e| Error::from_boxed_compat(Box::new(e)))
}

pub fn hash(data: &[u8]) -> String {
    let config = Config {
        ad: &[],
        hash_length: 64,
        lanes: 1,
        mem_cost: 8192,
        secret: &[],
        thread_mode: ThreadMode::Sequential,
        time_cost: 1,
        variant: Variant::Argon2d,
        version: Version::Version13,
    };

    let mut salt: [u8; 64] = [0; 64];
    thread_rng().fill(&mut salt[..]);

    argon2::hash_encoded(data, &salt, &config).unwrap()
}

pub fn verify(hash: &str, data: &[u8]) -> bool {
    argon2::verify_encoded(hash, data).unwrap()
}
