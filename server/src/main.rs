mod auth;
mod cache;
mod ratelimit;
mod util;
mod web;

use util::Result;
use log::LevelFilter;
fn main() -> Result<()> {
    simple_logging::log_to_stderr(LevelFilter::Debug);
    auth::prepare_db()?;
    web::start();
    Ok(())
}
