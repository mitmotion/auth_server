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
    ServerError(u16, String),
    RequestError(String),
    JsonError(serde_json::Error),
}

pub struct AuthClient {
    _agent: ureq::Agent,
    provider: String,
}

impl AuthClient {
    pub fn new<T: ToString>(provider: T) -> Self {
        Self {
            _agent: ureq::agent(),
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
        let resp = ureq::post(&ep).send_string(serde_json::to_string(&data)?.as_str());
        check_response(resp)?;
        Ok(())
    }

    pub fn username_to_uuid(&self, username: impl AsRef<str>) -> Result<Uuid, AuthClientError> {
        let data = UuidLookupPayload {
            username: username.as_ref().to_owned(),
        };
        let ep = format!("{}/username_to_uuid", self.provider);
        let resp = ureq::post(&ep).send_string(serde_json::to_string(&data)?.as_str());

        let resp = check_response(resp)?;
        let body = resp.into_string()?;
        let data: UuidLookupResponse = serde_json::from_str(body.as_str())?;
        Ok(data.uuid)
    }

    pub fn uuid_to_username(&self, uuid: Uuid) -> Result<String, AuthClientError> {
        let data = UsernameLookupPayload { uuid };
        let ep = format!("{}/uuid_to_username", self.provider);
        let resp = ureq::post(&ep).send_string(serde_json::to_string(&data)?.as_str());
        let resp = check_response(resp)?;
        let body = resp.into_string()?;
        let data: UsernameLookupResponse = serde_json::from_str(body.as_str())?;
        Ok(data.username)
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
        let resp = ureq::post(&ep).send_string(serde_json::to_string(&data)?.as_str());
        let resp = check_response(resp)?;
        let body = resp.into_string()?;
        let data: SignInResponse = serde_json::from_str(body.as_str())?;
        Ok(data.token)
    }

    pub fn validate(&self, token: AuthToken) -> Result<Uuid, AuthClientError> {
        let data = ValidityCheckPayload { token };
        let ep = format!("{}/verify", self.provider);
        let resp = ureq::post(&ep).send_string(serde_json::to_string(&data)?.as_str());
        let resp = check_response(resp)?;
        let body = resp.into_string()?;
        let data: ValidityCheckResponse = serde_json::from_str(body.as_str())?;
        Ok(data.uuid)
    }
}

fn check_response(resp: ureq::Response) -> Result<ureq::Response, AuthClientError> {
    match resp.synthetic_error() {
        Some(e) => Err(AuthClientError::RequestError(e.body_text())),
        None => {
            if resp.ok() {
                Ok(resp)
            } else {
                Err(AuthClientError::ServerError(
                    resp.status(),
                    resp.into_string().unwrap(),
                ))
            }
        }
    }
}

impl std::fmt::Display for AuthClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            AuthClientError::ServerError(code, text) => {
                write!(f, "Server returned {} with text {}", code, text)
            }
            AuthClientError::RequestError(text) => {
                write!(f, "Request failed, connection error with text {}", text)
            }
            AuthClientError::JsonError(err) => {
                write!(f, "failed json serialisation/deserialisation {}", err)
            }
        }
    }
}

impl From<serde_json::Error> for AuthClientError {
    fn from(err: serde_json::Error) -> Self {
        AuthClientError::JsonError(err)
    }
}

impl From<std::io::Error> for AuthClientError {
    fn from(err: std::io::Error) -> Self {
        AuthClientError::RequestError(format!("std::io::Error: {}", err))
    }
}
