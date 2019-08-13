use rouille::{router, Request, Response};

pub fn start() {
    rouille::start_server("0.0.0.0:19253", |req| handler(req));
}

fn handler(req: &Request) -> Response {
    router!(req,
        (GET) ["/ping"] => {
            Response::text("pong")
        },
        _ => {
            Response::empty_404()
        }
    )
}
