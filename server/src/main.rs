mod auth;
mod util;
mod web;
mod ezh;

use util::Result;

fn main() -> Result<()> {
    auth::prepare_db()?;
    web::start();
    Ok(())
}
