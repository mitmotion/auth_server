mod auth;
mod cache;
mod ratelimit;
mod util;
mod web;

use util::Result;
use log::LevelFilter;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn main() -> Result<()> {
    simple_logging::log_to_stderr(LevelFilter::Debug);
    auth::prepare_db()?;
    web::start();
    Ok(())
}
