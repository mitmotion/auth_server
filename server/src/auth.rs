use parking_lot::Mutex;
use lazy_static::lazy_static;
use rusqlite::types::ToSql;
use rusqlite::{params, Connection};
use crate::util::{Result, wrap_err};

static DB_NAME: &'static str = "data.sl3";

lazy_static! {
    static ref DB: Mutex<Connection> = Mutex::new(Connection::open(DB_NAME).unwrap());
}

pub fn prepare_db() {
    let conn = DB.lock();
}
