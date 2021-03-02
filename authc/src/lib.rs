use argon2::Config;
pub use auth_common::AuthToken;
use auth_common::{
    RegisterPayload, SignInPayload, SignInResponse, UsernameLookupPayload, UsernameLookupResponse,
    UuidLookupPayload, UuidLookupResponse, ValidityCheckPayload, ValidityCheckResponse,
};
pub use http::uri::Authority;
use http::Request;
use hyper::{body::to_bytes, client, Body, Uri};
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
    RequestError(hyper::Error),
    JsonError(serde_json::Error),
}
pub struct AuthClient {
    client: client::Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>, Body>,
    //precached Parts
    register_uri: Uri,
    username_to_uuid_uri: Uri,
    uuid_to_username_uri: Uri,
    generate_token_uri: Uri,
    verify_uri: Uri,
}

impl AuthClient {
    pub fn new(authority: Authority) -> Self {
        let https = hyper_rustls::HttpsConnector::with_native_roots();
        let client: client::Client<_, Body> = client::Client::builder().build(https);

        Self::with_client(authority, client)
    }

    pub fn with_client(
        authority: Authority,
        client: client::Client<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>, Body>,
    ) -> Self {
        let register_uri = Self::get_uri(&authority, "/register");
        let username_to_uuid_uri = Self::get_uri(&authority, "/username_to_uuid");
        let uuid_to_username_uri = Self::get_uri(&authority, "/uuid_to_username");
        let generate_token_uri = Self::get_uri(&authority, "/generate_token");
        let verify_uri = Self::get_uri(&authority, "/verify");

        Self {
            client,
            register_uri,
            username_to_uuid_uri,
            uuid_to_username_uri,
            generate_token_uri,
            verify_uri,
        }
    }

    async fn post<T>(
        &self,
        uri: &Uri,
        data: T,
    ) -> std::result::Result<http::Response<Body>, AuthClientError>
    where
        T: serde::ser::Serialize,
    {
        let body = serde_json::to_vec(&data)?;

        let mut request = Request::new(Body::from(body));
        *request.method_mut() = hyper::Method::POST;
        *request.uri_mut() = uri.clone();
        Ok(self.client.request(request).await?)
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

    fn get_uri(authority: &Authority, path: &'static str) -> Uri {
        Uri::builder()
            .scheme(http::uri::Scheme::HTTPS)
            .authority(authority.clone())
            .path_and_query(http::uri::PathAndQuery::from_static(path))
            .build()
            .expect("This URI should always be correct, so this will never panic")
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
async fn handle_response<T>(resp: hyper::Response<Body>) -> Result<T, AuthClientError>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let status = resp.status();
    let body = resp.into_body();
    let bytes = to_bytes(body).await?;

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
        }
    }
}

impl From<hyper::Error> for AuthClientError {
    fn from(err: hyper::Error) -> Self {
        AuthClientError::RequestError(err)
    }
}

impl From<serde_json::Error> for AuthClientError {
    fn from(err: serde_json::Error) -> Self {
        AuthClientError::JsonError(err)
    }
}
