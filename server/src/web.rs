use crate::auth::{self, AuthError};
use crate::ratelimit::RateLimiter;
use auth_common::{
    RegisterPayload, SignInPayload, SignInResponse, UsernameLookupPayload, UsernameLookupResponse,
    UuidLookupPayload, UuidLookupResponse, ValidityCheckPayload, ValidityCheckResponse,
};
use lazy_static::lazy_static;
use rouille::{router, start_server, Request, Response};
use std::error::Error;
use std::net::IpAddr;

lazy_static! {
    static ref RATELIMITER: RateLimiter = RateLimiter::new();
}

const USERNAME_MAX_LEN: usize = 32;

fn verify_username(username: &str) -> Result<(), AuthError> {
    if username.len() > USERNAME_MAX_LEN {
        Err(AuthError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn err_handle<E: Error>(f: impl FnOnce() -> Result<Response, E>) -> Response {
    match f() {
        Ok(response) => response,
        Err(err) => Response::text(format!("{}", err)).with_status_code(500),
    }
}

fn ratelimit(
    req: &Request,
    f: fn(&Request) -> Result<Response, AuthError>,
) -> Result<Response, AuthError> {
    if RATELIMITER.check(remote(req)) {
        f(req)
    } else {
        Err(AuthError::RateLimit)
    }
}

fn remote(req: &Request) -> IpAddr {
    req.header("X-Real-IP")
        .map(|ip| ip.parse().unwrap_or(req.remote_addr().ip()))
        .unwrap_or(req.remote_addr().ip())
}

fn ping(req: &Request) -> Response {
    Response::text(format!("Ping! {}", remote(req).to_string()))
}

fn username_to_uuid(req: &Request) -> Result<Response, AuthError> {
    let body = req.data().unwrap();
    let payload: UuidLookupPayload = serde_json::from_reader(body)?;
    let uuid = auth::username_to_uuid(&payload.username)?;
    let response = UuidLookupResponse { uuid };
    Ok(Response::json(&response))
}

fn uuid_to_username(req: &Request) -> Result<Response, AuthError> {
    let body = req.data().unwrap();
    let payload: UsernameLookupPayload = serde_json::from_reader(body)?;
    let username = auth::uuid_to_username(&payload.uuid)?;
    let response = UsernameLookupResponse { username };
    Ok(Response::json(&response))
}

fn register(req: &Request) -> Result<Response, AuthError> {
    let body = req.data().unwrap();
    let payload: RegisterPayload = serde_json::from_reader(body)?;
    verify_username(&payload.username)?;
    auth::register(&payload.username, &payload.password)?;
    Ok(Response::text("Ok"))
}

fn generate_token(req: &Request) -> Result<Response, AuthError> {
    let body = req.data().unwrap();
    let payload: SignInPayload = serde_json::from_reader(body)?;
    verify_username(&payload.username)?;
    let token = auth::generate_token(&payload.username, &payload.password)?;
    let response = SignInResponse { token };
    Ok(Response::json(&response))
}

fn verify(req: &Request) -> Result<Response, AuthError> {
    let body = req.data().unwrap();
    let payload: ValidityCheckPayload = serde_json::from_reader(body)?;
    let uuid = auth::verify(payload.token)?;
    let response = ValidityCheckResponse { uuid };
    Ok(Response::json(&response))
}

pub fn start() {
    start_server("0.0.0.0:19253", move |request| {
        router!(request,
            (GET) (/ping) => {
                ping(request)
            },

            (POST) (/username_to_uuid) => {
                err_handle(|| username_to_uuid(request))
            },

            (POST) (/uuid_to_username) => {
                err_handle(|| uuid_to_username(request))
            },

            (POST) (/register) => {
                err_handle(|| ratelimit(request, register))
            },

            (POST) (/generate_token) => {
                err_handle(|| ratelimit(request, generate_token))
            },

            (POST) (/verify) => {
                err_handle(|| verify(request))
            },

            _ => Response::empty_404()
        )
    });
}
