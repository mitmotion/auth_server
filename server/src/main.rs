mod auth;
mod cache;
mod ratelimit;
mod util;
mod web;

use log::LevelFilter;
use util::Result;
fn main() -> Result<()> {
    simple_logging::log_to_stderr(LevelFilter::Debug);
    auth::prepare_db()?;
    web::start();
    Ok(())
}
