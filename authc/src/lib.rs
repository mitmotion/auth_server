use argon2::Config;
pub use auth_common::AuthToken;
use auth_common::{
    RegisterPayload, SignInPayload, SignInResponse, UsernameLookupPayload, UsernameLookupResponse,
    UuidLookupPayload, UuidLookupResponse, ValidityCheckPayload, ValidityCheckResponse,
};
pub use uuid::Uuid;

fn net_prehash(password: &str) -> String {
    let salt = fxhash::hash64(password);
    let config = Config::default();
    let bytes = argon2::hash_raw(password.as_bytes(), &salt.to_le_bytes(), &config).unwrap();
    hex::encode(&bytes)
}

#[derive(Debug)]
pub enum AuthClientError {
    // Server did not return 200-299 StatusCode.
    ServerError(reqwest::StatusCode, String),
    RequestError(reqwest::Error),
    JsonError(serde_json::Error),
}

pub struct AuthClient {
    http: reqwest::blocking::Client,
    provider: String,
}

impl AuthClient {
    pub fn new<T: ToString>(provider: T) -> Self {
        Self {
            http: reqwest::blocking::Client::new(),
            provider: provider.to_string(),
        }
    }

    pub fn register(
        &self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<(), AuthClientError> {
        let data = RegisterPayload {
            username: username.as_ref().to_owned(),
            password: net_prehash(password.as_ref()),
        };
        let ep = format!("{}/register", self.provider);
        let resp = self
            .http
            .post(&ep)
            .body(serde_json::to_string(&data)?)
            .send()?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(AuthClientError::ServerError(
                resp.status(),
                resp.text().unwrap(),
            ))
        }
    }

    pub fn username_to_uuid(&self, username: impl AsRef<str>) -> Result<Uuid, AuthClientError> {
        let data = UuidLookupPayload {
            username: username.as_ref().to_owned(),
        };
        let ep = format!("{}/username_to_uuid", self.provider);
        let resp = self
            .http
            .post(&ep)
            .body(serde_json::to_string(&data)?)
            .send()?;
        if resp.status().is_success() {
            let body = resp.text()?;
            let data: UuidLookupResponse = serde_json::from_str(body.as_str())?;
            Ok(data.uuid)
        } else {
            Err(AuthClientError::ServerError(
                resp.status(),
                resp.text().unwrap(),
            ))
        }
    }

    pub fn uuid_to_username(&self, uuid: Uuid) -> Result<String, AuthClientError> {
        let data = UsernameLookupPayload { uuid };
        let ep = format!("{}/uuid_to_username", self.provider);
        let resp = self
            .http
            .post(&ep)
            .body(serde_json::to_string(&data)?)
            .send()?;
        if resp.status().is_success() {
            let body = resp.text()?;
            let data: UsernameLookupResponse = serde_json::from_str(body.as_str())?;
            Ok(data.username)
        } else {
            Err(AuthClientError::ServerError(
                resp.status(),
                resp.text().unwrap(),
            ))
        }
    }

    pub fn sign_in(
        &self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<AuthToken, AuthClientError> {
        let data = SignInPayload {
            username: username.as_ref().to_owned(),
            password: net_prehash(password.as_ref()),
        };
        let ep = format!("{}/generate_token", self.provider);
        let resp = self
            .http
            .post(&ep)
            .body(serde_json::to_string(&data)?)
            .send()?;
        if resp.status().is_success() {
            let body = resp.text()?;
            let data: SignInResponse = serde_json::from_str(body.as_str())?;
            Ok(data.token)
        } else {
            Err(AuthClientError::ServerError(
                resp.status(),
                resp.text().unwrap(),
            ))
        }
    }

    pub fn validate(&self, token: AuthToken) -> Result<Uuid, AuthClientError> {
        let data = ValidityCheckPayload { token };
        let ep = format!("{}/verify", self.provider);
        let resp = self
            .http
            .post(&ep)
            .body(serde_json::to_string(&data)?)
            .send()?;
        if resp.status().is_success() {
            let body = resp.text()?;
            let data: ValidityCheckResponse = serde_json::from_str(body.as_str())?;
            Ok(data.uuid)
        } else {
            Err(AuthClientError::ServerError(
                resp.status(),
                resp.text().unwrap(),
            ))
        }
    }
}

impl std::fmt::Display for AuthClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            AuthClientError::ServerError(code, text) => {
                write!(f, "Server returned {} with text {}", code, text)
            }
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
