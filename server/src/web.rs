use crate::auth;
use crate::util::Result;
use auth_common::{AuthToken, SignInResponse, UuidLookupResponse, ValidityCheckResponse};
use failure::Fail;
use rouille::{router, Request, Response};
use std::net::SocketAddr;

#[derive(Debug, Fail)]
enum RequestError {
    #[fail(display = "MissingField")]
    MissingField,
}

pub fn start() {
    rouille::start_server("0.0.0.0:19253", |req| handler(req));
}

fn handler(req: &Request) -> Response {
    router!(req,
        (GET) ["/ping"] => {
            Response::text("pong")
        },
        (GET) ["/api/v1/register"] => {
            err_handler(handler_api_v1_register(req))
        },
        (GET) ["/api/v1/utuuid"] => {
            err_handler(handler_api_v1_username_to_uuid(req))
        },
        (GET) ["/api/v1/signin"] => {
            err_handler(handler_api_v1_signin(req))
        },
        (GET) ["/api/v1/validate"] => {
            err_handler(handler_api_v1_validate(req))
        },
        _ => {
            Response::empty_404()
        }
    )
}

fn err_handler(t: Result<Response>) -> Response {
    if let Ok(r) = t {
        r
    } else {
        Response::empty_404()
    }
}

fn get_field(req: &Request, field: &str) -> Result<String> {
    let maybe: Option<String> = req.get_param(field);
    let rmaybe: Result<String> = maybe.ok_or(RequestError::MissingField.into());
    rmaybe
}

fn handler_api_v1_register(req: &Request) -> Result<Response> {
    let username = get_field(req, "username")?;
    let password = get_field(req, "password")?;
    auth::register(username, password)?;
    Ok(Response::text("success"))
}

fn handler_api_v1_username_to_uuid(req: &Request) -> Result<Response> {
    let username = get_field(req, "username")?;
    let uuid = auth::username_to_uuid(username)?;
    let response = UuidLookupResponse { uuid };
    Ok(Response::json(&response))
}

fn handler_api_v1_signin(req: &Request) -> Result<Response> {
    let username = get_field(req, "username")?;
    let password = get_field(req, "password")?;
    let server = get_field(req, "server")?.parse()?;
    let token = auth::generate_token(username, password, server)?;
    let response = SignInResponse { token };
    Ok(Response::json(&response))
}

fn handler_api_v1_validate(req: &Request) -> Result<Response> {
    let token = AuthToken::deserialize(&get_field(req, "token")?);
    let remote = if let SocketAddr::V4(addr) = req.remote_addr().clone() {
        addr.ip().clone()
    } else {
        unreachable!();
    };
    let uuid = auth::verify_token(remote, token)?;
    let response = ValidityCheckResponse { uuid };
    Ok(Response::json(&response))
}
