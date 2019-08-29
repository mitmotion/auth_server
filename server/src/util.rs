use argon2::{Config, ThreadMode, Variant, Version};
use failure::Error;
use rand::prelude::*;
use std::error::Error as StdError;
use std::result::Result as StdResult;

pub type Result<T> = StdResult<T, Error>;

pub fn wrap_err<T, E: 'static + StdError + Sync + Send>(r: StdResult<T, E>) -> Result<T> {
    r.map_err(|e| Error::from_boxed_compat(Box::new(e)))
}

const ARGON2CONFIG: Config = Config {
    ad: &[],
    hash_length: 128,
    lanes: 1,
    mem_cost: 4096,
    secret: &[],
    thread_mode: ThreadMode::Sequential,
    time_cost: 1,
    variant: Variant::Argon2d,
    version: Version::Version13,
};

pub fn hash(data: &[u8]) -> String {
    let mut salt: [u8; 128] = [0; 128];
    thread_rng().fill(&mut salt[..]);

    argon2::hash_encoded(data, &salt, &ARGON2CONFIG).unwrap()
}

pub fn verify(hash: &str, data: &[u8]) -> bool {
    argon2::verify_encoded(hash, data).unwrap()
}
