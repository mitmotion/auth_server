mod auth;
mod util;

use util::Result;

fn main() -> Result<()> {
    auth::prepare_db()?;
    println!("Hello, world!");
    Ok(())
}
