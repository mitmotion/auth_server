mod auth;
mod cache;
mod util;
mod web;

use util::Result;

fn main() -> Result<()> {
    auth::prepare_db()?;
    web::start();
    Ok(())
}
