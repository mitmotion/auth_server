use std::error::Error as StdError;
use std::result::Result as StdResult;
use failure::Error;

pub type Result<T> = StdResult<T, Error>;

pub fn wrap_err<T, E: 'static + StdError + Sync + Send>(r: StdResult<T, E>) -> Result<T> {
    r.map_err(|e| Error::from_boxed_compat(Box::new(e)))
}
