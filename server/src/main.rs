mod auth;
mod cache;
mod ratelimit;
mod util;
mod web;

use util::Result;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn main() -> Result<()> {
    auth::prepare_db()?;
    web::start();
    Ok(())
}
