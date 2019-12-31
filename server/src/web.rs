use crate::auth::{self, AuthError};
use auth_common::{
    RegisterPayload, SignInPayload, SignInResponse, UsernameLookupPayload, UsernameLookupResponse,
    UuidLookupPayload, UuidLookupResponse, ValidityCheckPayload, ValidityCheckResponse,
};
use rouille::{router, start_server, Request, Response};
use std::error::Error;

fn err_handle<E: Error>(f: impl FnOnce() -> Result<Response, E>) -> Response {
    match f() {
        Ok(response) => response,
        Err(err) => Response::text(format!("{}", err)).with_status_code(500),
    }
}

fn ping(req: &Request) -> Response {
    Response::text(format!("Ping! {}", req.remote_addr().ip()))
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
    auth::register(&payload.username, &payload.password)?;
    Ok(Response::text("Ok"))
}

fn generate_token(req: &Request) -> Result<Response, AuthError> {
    let body = req.data().unwrap();
    let payload: SignInPayload = serde_json::from_reader(body)?;
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
    start_server("0.0.0.0:19583", move |request| {
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
                err_handle(|| register(request))
            },

            (POST) (/generate_token) => {
                err_handle(|| generate_token(request))
            },

            (POST) (/verify) => {
                err_handle(|| verify(request))
            },

            _ => Response::empty_404()
        )
    });
}
