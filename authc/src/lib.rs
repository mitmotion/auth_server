pub use auth_common::AuthToken;
use auth_common::{SignInResponse, UuidLookupResponse, ValidityCheckResponse};
use std::env;
use std::net::Ipv4Addr;
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

    pub fn username_to_uuid(&self, username: impl AsRef<str>) -> Result<Uuid, AuthClientError> {
        let username = username.as_ref();
        let ep = format!("{}/api/v1/utuuid", self.provider);
        let mut resp = self.http.get(&ep).query(&[("username", username)]).send()?;
        if resp.status().is_success() {
            let body = resp.text()?;
            let data: UuidLookupResponse = serde_json::from_str(body.as_str())?;
            Ok(data.uuid)
        } else {
            Err(AuthClientError::GenericError)
        }
    }

    pub fn sign_in(
        &self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
        server: Ipv4Addr,
    ) -> Result<AuthToken, AuthClientError> {
        let username = username.as_ref();
        let password = password.as_ref();
        let server = server.to_string();
        let server = server.as_str();
        let ep = format!("{}/api/v1/signin", self.provider);
        let mut resp = self
            .http
            .get(&ep)
            .query(&[
                ("username", username),
                ("password", password),
                ("server", server),
            ])
            .send()?;
        if resp.status().is_success() {
            let body = resp.text()?;
            let data: SignInResponse = serde_json::from_str(body.as_str())?;
            Ok(data.token)
        } else {
            Err(AuthClientError::GenericError)
        }
    }

    pub fn validate(&self, token: AuthToken) -> Result<Uuid, AuthClientError> {
        let token = token.serialize();
        let token = token.as_str();
        let ep = format!("{}/api/v1/validate", self.provider);
        let mut resp = self.http.get(&ep).query(&[("token", token)]).send()?;
        if resp.status().is_success() {
            let body = resp.text()?;
            let data: ValidityCheckResponse = serde_json::from_str(body.as_str())?;
            Ok(data.uuid)
        } else {
            Err(AuthClientError::GenericError)
        }
    }
}
