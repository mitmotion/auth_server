pub use auth_common::AuthToken;
use auth_common::{SignInResponse, UuidLookupResponse, ValidityCheckResponse};
use std::env;
use std::net::Ipv4Addr;
pub use uuid::Uuid;

fn resolve_provider() -> String {
    env::var("VELOREN_AUTH_PROVIDER").unwrap_or("https://auth.veloren.net".to_owned())
}

pub enum AuthClientError {
    // Server did not return 200-299 StatusCode.
    ServerError(reqwest::StatusCode),
    RequestError(reqwest::Error),
    JsonError(serde_json::Error),
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
            Err(AuthClientError::ServerError(resp.status()))
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
            Err(AuthClientError::ServerError(resp.status()))
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
            Err(AuthClientError::ServerError(resp.status()))
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
            Err(AuthClientError::ServerError(resp.status()))
        }
    }
}

impl std::fmt::Display for AuthClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            AuthClientError::ServerError(code) => write!(f, "Server returned {}", code),
            AuthClientError::RequestError(err) => write!(f, "Request failed {}", err),
            AuthClientError::JsonError(err) => {
                write!(f, "failed json serialisation/deserialisation {}", err)
            }
        }
    }
}

impl From<reqwest::Error> for AuthClientError {
    fn from(err: reqwest::Error) -> Self {
        AuthClientError::RequestError(err)
    }
}

impl From<serde_json::Error> for AuthClientError {
    fn from(err: serde_json::Error) -> Self {
        AuthClientError::JsonError(err)
    }
}
