use argon2::Config;
pub use auth_common::AuthToken;
use auth_common::{
    RegisterPayload, SignInPayload, SignInResponse, UsernameLookupPayload, UsernameLookupResponse,
    UuidLookupPayload, UuidLookupResponse, ValidityCheckPayload, ValidityCheckResponse,
};
pub use reqwest::Url;
use reqwest::{Client, Response};
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
    ServerError(u16, Vec<u8>),
    RequestError(reqwest::Error),
    JsonError(serde_json::Error),
    InvalidUrl(url::ParseError),
    InsecureSchema,
}
pub struct AuthClient {
    client: Client,
    //precached Parts
    register_uri: Url,
    username_to_uuid_uri: Url,
    uuid_to_username_uri: Url,
    generate_token_uri: Url,
    verify_uri: Url,
}

impl AuthClient {
    pub fn new(scheme: &str, schema: &str) -> Result<Self, AuthClientError> {
        let client = Client::new();

        Self::with_client(scheme, schema, client)
    }

    pub fn with_client(
        scheme: &str,
        schema: &str,
        client: Client,
    ) -> Result<Self, AuthClientError> {
        let base = Url::parse(&format!("{}://{}", scheme, schema))?;

        // enforce HTTPS except `localhost` and/or `debug` build
        #[cfg(not(debug_assertions))]
        {
            if base.scheme() == "http"
                && !matches!(base.host(), Some(url::Host::Domain("localhost")))
            {
                return Err(AuthClientError::InsecureSchema);
            }
        }

        let build_uri = |host: &Url, path: &'static str| {
            let mut url = host.clone();
            url.set_path(path);
            url
        };

        let register_uri = build_uri(&base, "/register");
        let username_to_uuid_uri = build_uri(&base, "/username_to_uuid");
        let uuid_to_username_uri = build_uri(&base, "/uuid_to_username");
        let generate_token_uri = build_uri(&base, "/generate_token");
        let verify_uri = build_uri(&base, "/verify");

        Ok(Self {
            client,
            register_uri,
            username_to_uuid_uri,
            uuid_to_username_uri,
            generate_token_uri,
            verify_uri,
        })
    }

    async fn post<T>(&self, url: &Url, data: T) -> Result<Response, AuthClientError>
    where
        T: serde::ser::Serialize,
    {
        let body = serde_json::to_vec(&data)?;

        Ok(self.client.post(url.clone()).body(body).send().await?)
    }

    pub async fn register(
        &self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<(), AuthClientError> {
        let data = RegisterPayload {
            username: username.as_ref().to_owned(),
            password: net_prehash(password.as_ref()),
        };
        self.post(&self.register_uri, data).await?;
        Ok(())
    }

    pub async fn username_to_uuid(
        &self,
        username: impl AsRef<str>,
    ) -> Result<Uuid, AuthClientError> {
        let data = UuidLookupPayload {
            username: username.as_ref().to_owned(),
        };
        let resp = self.post(&self.username_to_uuid_uri, data).await?;

        Ok(handle_response::<UuidLookupResponse>(resp).await?.uuid)
    }

    pub async fn uuid_to_username(&self, uuid: Uuid) -> Result<String, AuthClientError> {
        let data = UsernameLookupPayload { uuid };
        let resp = self.post(&self.uuid_to_username_uri, data).await?;

        Ok(handle_response::<UsernameLookupResponse>(resp)
            .await?
            .username)
    }

    pub async fn sign_in(
        &self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<AuthToken, AuthClientError> {
        let data = SignInPayload {
            username: username.as_ref().to_owned(),
            password: net_prehash(password.as_ref()),
        };
        let resp = self.post(&self.generate_token_uri, data).await?;

        Ok(handle_response::<SignInResponse>(resp).await?.token)
    }

    pub async fn validate(&self, token: AuthToken) -> Result<Uuid, AuthClientError> {
        let data = ValidityCheckPayload { token };
        let resp = self.post(&self.verify_uri, data).await?;

        Ok(handle_response::<ValidityCheckResponse>(resp).await?.uuid)
    }
}

/// If response code isn't a success it will return an error with the response code and plain text body.
///
/// Otherwise will deserialize the json based on given type (through turbofish notation)
async fn handle_response<T>(resp: Response) -> Result<T, AuthClientError>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let status = resp.status();
    let bytes = resp.bytes().await?;

    if status.is_success() {
        Ok(serde_json::from_slice(&bytes)?)
    } else {
        Err(AuthClientError::ServerError(
            status.as_u16(),
            bytes.to_vec(),
        ))
    }
}

impl std::fmt::Display for AuthClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            AuthClientError::ServerError(code, text) => {
                write!(f, "Auth Server returned {} with: {:?}", code, text)
            }
            AuthClientError::RequestError(text) => write!(f, "Request failed with: {}", text),
            AuthClientError::JsonError(text) => write!(f, "Failed to convert Json with: {}", text),
            AuthClientError::InvalidUrl(text) => write!(f, "Failed to parse Url: {}", text),
            AuthClientError::InsecureSchema => write!(f, "Using auth with `HTTP` is insecure. It's only allowed to use HTTP if the authority is `localhost` or when debug_assertions are set"),
        }
    }
}

impl From<url::ParseError> for AuthClientError {
    fn from(err: url::ParseError) -> Self {
        AuthClientError::InvalidUrl(err)
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
