use argon2::Config;
pub use auth_common::AuthToken;
use auth_common::{
    RegisterPayload, SignInPayload, SignInResponse, UsernameLookupPayload, UsernameLookupResponse,
    UuidLookupPayload, UuidLookupResponse, ValidityCheckPayload, ValidityCheckResponse,
};
use core::marker::PhantomData;
use reqwest::{IntoUrl, Url};
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
    RequestError(reqwest::Error),
    InvalidUrl(Option<url::ParseError>),
    ParseError(serde_json::Error),
}
pub struct AuthClient {
    client: reqwest::Client,
    provider: Url,
}

pub struct AuthRequest<Response> {
    request: reqwest::Request,
    response: PhantomData<Response>,
}

impl<Response> Clone for AuthRequest<Response> {
    fn clone(&self) -> Self {
        Self {
            request: self
                .request
                .try_clone()
                // The only place a body can be set on an AuthRequest request is within this
                // module, and we never clone afterwards here.
                .expect("Request does not have a body, so the clone must succeed."),
            response: PhantomData,
        }
    }
}

impl<Response> AuthRequest<Response> {
    /// Invariant: endpoint should be a valid URI path.
    fn new(client: &AuthClient, endpoint: &'static str) -> Result<Self, AuthClientError> {
        Ok(Self {
            request: client.client
                .post(client.provider.join(endpoint)?)
                .header(reqwest::header::CONTENT_TYPE, reqwest::header::HeaderValue::from_static("application/json"))
                .build()
                // In this module, we only pass in valid endpoints, so this must succeed.
                .expect("All the endpoints in this module are valid, and the headers are always the same."),
            response: PhantomData,
        })
    }

    /// Execute the current `AuthRequest`.
    pub async fn execute(
        mut self,
        payload: reqwest::Body,
        client: &AuthClient,
    ) -> Result<Response, AuthClientError>
    where
        Response: serde::Serialize + serde::de::DeserializeOwned,
    {
        *self.request.body_mut() = Some(payload);
        Ok(handle_response::<Response>(client.client.execute(self.request).await?).await?)
    }
}

//// Default client settings are designed to be as low-latency as reasonably possible while
/// still being completely predictable for short message sizes.  This is beacause the
/// validate endpoint creates server-side state for unauthenticated clients, so we want it
/// to be resolved as quickly as possible.
///
/// For pool values, timeouts, sockets, etc., values are set deliberately low to avoid
/// consuming extra resources except when requested to do so.  If the client has
/// high-performance needs they should set these using `with_client`.
pub fn default_client_config() -> reqwest::ClientBuilder {
    reqwest::ClientBuilder::new()
        // NOTE: The default proxy is System and we want to keep it, and similarly the default
        // is no timeout or connect_timeout, but we can't explicitly specify these.
        // .proxy(Proxy::System)
        // .timeout(None)
        // .connect_timeout(None)
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .pool_idle_timeout(None)
        .pool_max_idle_per_host(1)
        .tcp_nodelay_(true)
        .local_address(None)
}

impl AuthClient {
    pub fn with_client<T: IntoUrl>(
        provider: T,
        client: reqwest::ClientBuilder,
    ) -> Result<Self, AuthClientError> {
        Ok(Self {
            client: client
                // Unsupported options.
                .no_gzip()
                .no_brotli()
                // To avoid leaking sensitive information.
                .connection_verbose(false)
                // NOTE: Ideally we could set identity here to match the provider.
                // .identity(???)
                // NOTE: Not possible iwth rust-tls.
                // .danger_accept_invalid_hostnames(false)
                // No insecure TLS ooptions
                .danger_accept_invalid_certs(false)
                // No C TLS.
                .use_rustls_tls()
                // No C DNS calls or blocking spawn
                .trust_dns(true)
                .build()?,
            provider: provider.into_url()?,
        })
    }

    pub fn new<T: IntoUrl>(provider: T) -> Result<Self, AuthClientError> {
        Self::with_client(provider, default_client_config())
    }

    pub async fn register(
        &self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<(), AuthClientError> {
        Ok(AuthRequest::<()>::new(self, "register")?
            .execute(
                serde_json::to_vec(&RegisterPayload {
                    username: username.as_ref().to_owned(),
                    password: net_prehash(password.as_ref()),
                })?
                .into(),
                self,
            )
            .await?)
    }

    pub async fn username_to_uuid(
        &self,
        username: impl AsRef<str>,
    ) -> Result<Uuid, AuthClientError> {
        Ok(
            AuthRequest::<UuidLookupResponse>::new(self, "username_to_uuid")?
                .execute(
                    serde_json::to_vec(&UuidLookupPayload {
                        username: username.as_ref().to_owned(),
                    })?
                    .into(),
                    self,
                )
                .await?
                .uuid,
        )
    }

    pub async fn uuid_to_username(&self, uuid: Uuid) -> Result<String, AuthClientError> {
        Ok(
            AuthRequest::<UsernameLookupResponse>::new(self, "uuid_to_username")?
                .execute(
                    serde_json::to_vec(&UsernameLookupPayload { uuid })?.into(),
                    self,
                )
                .await?
                .username,
        )
    }

    pub async fn sign_in(
        &self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<AuthToken, AuthClientError> {
        Ok(AuthRequest::<SignInResponse>::new(self, "generate_token")?
            .execute(
                serde_json::to_vec(&SignInPayload {
                    username: username.as_ref().to_owned(),
                    password: net_prehash(password.as_ref()),
                })?
                .into(),
                self,
            )
            .await?
            .token)
    }

    /// Get a cached client for subsequent validation.
    pub fn validation_request(
        &self,
    ) -> Result<AuthRequest<ValidityCheckResponse>, AuthClientError> {
        AuthRequest::new(self, "verify")
    }

    pub async fn validate(&self, token: AuthToken) -> Result<Uuid, AuthClientError> {
        Ok(self
            .validation_request()?
            .execute(
                serde_json::to_vec(&ValidityCheckPayload { token })?.into(),
                self,
            )
            .await?
            .uuid)
    }
}

/// If response code isn't a success it will return an error with the response code and plain text body.
///
/// Otherwise will deserialize the json based on given type (through turbofish notation)
async fn handle_response<T>(resp: reqwest::Response) -> Result<T, AuthClientError>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    if resp.status().is_success() {
        Ok(resp.json::<T>().await?)
    } else {
        Err(AuthClientError::ServerError(
            resp.status().as_u16(),
            resp.text().await?,
        ))
    }
}

impl std::fmt::Display for AuthClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            AuthClientError::ServerError(code, text) => {
                write!(f, "Auth Server returned {} with: {}", code, text)
            }
            AuthClientError::RequestError(text) => write!(f, "Request failed with: {}", text),
            AuthClientError::InvalidUrl(e) => {
                write!(f, "Got invalid url to make auth requests to: {:?}", e)
            }
            AuthClientError::ParseError(err) => write!(f, "Request failed with: {}", err),
        }
    }
}

impl From<url::ParseError> for AuthClientError {
    fn from(err: url::ParseError) -> Self {
        AuthClientError::InvalidUrl(Some(err))
    }
}

impl From<reqwest::Error> for AuthClientError {
    fn from(err: reqwest::Error) -> Self {
        AuthClientError::RequestError(err)
    }
}

impl From<serde_json::Error> for AuthClientError {
    fn from(err: serde_json::Error) -> Self {
        AuthClientError::ParseError(err)
    }
}
