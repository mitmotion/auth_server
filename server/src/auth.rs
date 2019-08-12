use parking_lot::Mutex;
use lazy_static::lazy_static;
use rusqlite::{params, Connection};
use crate::util::{Result, wrap_err};

static DB_NAME: &'static str = "data.sl3";

lazy_static! {
    static ref DB: Mutex<Connection> = Mutex::new(Connection::open(DB_NAME).unwrap());
}

pub fn prepare_db() -> Result<()> {
    let conn = DB.lock();

    wrap_err(conn.execute(
        "CREATE TABLE IF NOT EXISTS accounts (
                  id              TEXT PRIMARY KEY,
                  username        TEXT NOT NULL,
                  phash           TEXT NOT NULL
        )",
        params![],
    ))?;

    wrap_err(conn.execute(
        "CREATE TABLE IF NOT EXISTS keys (
                  key             TEXT PRIMARY KEY,
                  user_id         TEXT NOT NULL
        )",
        params![],
    ))?;

    Ok(())
}
