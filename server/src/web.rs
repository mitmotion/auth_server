use crate::auth;
use crate::ratelimit::RateLimiter;
use crate::util::Result;
use auth_common::{
    RegisterPayload, SignInPayload, SignInResponse, UuidLookupPayload, UuidLookupResponse,
    ValidityCheckPayload, ValidityCheckResponse,
};
use lazy_static::lazy_static;
use rouille::{router, Request, Response};
use std::io::Read;
use std::net::SocketAddr;

lazy_static! {
    static ref RATELIMITER: RateLimiter = RateLimiter::new();
}

pub fn start() {
    rouille::start_server("0.0.0.0:19253", |req| handler(req));
}

fn handler(req: &Request) -> Response {
    router!(req,
        (GET) ["/ping"] => {
            Response::text("pong")
        },
        (POST) ["/api/v1/register"] => {
            rr_or_404(req, |req| err_handler(handler_api_v1_register(req)))
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

fn rr_or_404(req: &Request, f: impl FnOnce(&Request) -> Response) -> Response {
    let addr = req.remote_addr().ip();
    if RATELIMITER.check(addr) {
        f(req)
    } else {
        Response::empty_404()
    }
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
    let remote = if let SocketAddr::V4(addr) = req.remote_addr() {
        *addr.ip()
    } else {
        unreachable!();
    };
    let uuid = auth::verify_token(remote, data.token)?;
    let response = ValidityCheckResponse { uuid };
    Ok(Response::json(&response))
}
