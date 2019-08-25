use crate::auth;
use crate::util::Result;
use auth_common::{
    RegisterPayload, SignInPayload, SignInResponse, UuidLookupPayload, UuidLookupResponse,
    ValidityCheckPayload, ValidityCheckResponse,
};
use rouille::{router, Request, Response};
use std::io::Read;
use std::net::SocketAddr;

pub fn start() {
    rouille::start_server("0.0.0.0:19253", |req| handler(req));
}

fn handler(req: &Request) -> Response {
    router!(req,
        (POST) ["/ping"] => {
            Response::text("pong")
        },
        (POST) ["/api/v1/register"] => {
            err_handler(handler_api_v1_register(req))
        },
        (POST) ["/api/v1/utuuid"] => {
            err_handler(handler_api_v1_username_to_uuid(req))
        },
        (POST) ["/api/v1/signin"] => {
            err_handler(handler_api_v1_signin(req))
        },
        (POST) ["/api/v1/validate"] => {
            err_handler(handler_api_v1_validate(req))
        },
        _ => {
            Response::empty_404()
        }
    )
}

fn err_handler(t: Result<Response>) -> Response {
    match t {
        Ok(r) => r,
        Err(why) => {
            println!("{:?}", why);
            Response::empty_404()
        }
    }
}

fn get_post_body(req: &Request) -> String {
    let mut buf = String::new();
    req.data().unwrap().read_to_string(&mut buf).unwrap();
    buf
}

fn handler_api_v1_register(req: &Request) -> Result<Response> {
    let data: RegisterPayload = serde_json::from_str(&get_post_body(req))?;
    auth::register(data.username, data.password, data.email)?;
    Ok(Response::text("success"))
}

fn handler_api_v1_username_to_uuid(req: &Request) -> Result<Response> {
    let data: UuidLookupPayload = serde_json::from_str(&get_post_body(req))?;
    let uuid = auth::username_to_uuid(data.username)?;
    let response = UuidLookupResponse { uuid };
    Ok(Response::json(&response))
}

fn handler_api_v1_signin(req: &Request) -> Result<Response> {
    let data: SignInPayload = serde_json::from_str(&get_post_body(req))?;
    let token = auth::generate_token(data.username, data.password, data.server.parse()?)?;
    let response = SignInResponse { token };
    Ok(Response::json(&response))
}

fn handler_api_v1_validate(req: &Request) -> Result<Response> {
    let data: ValidityCheckPayload = serde_json::from_str(&get_post_body(req))?;
    let remote = if let SocketAddr::V4(addr) = req.remote_addr().clone() {
        addr.ip().clone()
    } else {
        unreachable!();
    };
    let uuid = auth::verify_token(remote, data.token)?;
    let response = ValidityCheckResponse { uuid };
    Ok(Response::json(&response))
}
