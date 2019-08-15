pub use auth_common::AuthToken;
use std::env;
pub use uuid::Uuid;

fn resolve_provider() -> String {
    env::var("VELOREN_AUTH_PROVIDER").unwrap_or("https://auth.veloren.net".to_owned())
}

pub enum AuthClientError {
    GenericError,
}

impl<E: std::error::Error> From<E> for AuthClientError {
    fn from(_error: E) -> Self {
        AuthClientError::GenericError
    }
}

pub struct AuthClient {
    http: reqwest::Client,
    provider: String,
}

impl AuthClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            provider: resolve_provider(),
        }
    }

    pub fn register(
        &self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<(), AuthClientError> {
        let username = username.as_ref();
        let password = password.as_ref();
        let ep = format!("{}/api/v1/register", self.provider);
        let resp = self
            .http
            .get(&ep)
            .query(&[("username", username), ("password", password)])
            .send()?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(AuthClientError::GenericError)
        }
    }
}
