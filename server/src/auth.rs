use parking_lot::Mutex;
use lazy_static::lazy_static;
use rusqlite::{params, Connection};
use crate::util::{Result, wrap_err};
use failure::Fail;
use time::Timespec;
use bcrypt::{DEFAULT_COST, hash, verify};
use uuid::Uuid;

static DB_NAME: &'static str = "data.sl3";

lazy_static! {
    static ref DB: Mutex<Connection> = Mutex::new(Connection::open(DB_NAME).unwrap());
}

pub fn prepare_db() -> Result<()> {
    let conn = DB.lock();

    wrap_err(conn.execute(
        "CREATE TABLE IF NOT EXISTS accounts (
                  id              TEXT PRIMARY KEY UNIQUE,
                  username        TEXT NOT NULL,
                  phash           TEXT NOT NULL
        )",
        params![],
    ))?;

    wrap_err(conn.execute(
        "CREATE TABLE IF NOT EXISTS keys (
                  key             TEXT PRIMARY KEY,
                  user_id         TEXT NOT NULL,
                  created_at      TEXT NOT NULL,
        )",
        params![],
    ))?;

    Ok(())
}

struct RawAccount {
    id: String,
    username: String,
    phash: String,
}

#[derive(Debug, Fail)]
enum RegisterError {
    #[fail(display = "UsernameTaken")]
    UsernameTaken,
}

pub fn register(username: String, password: String) -> Result<()> {
    let phash = hash(password, DEFAULT_COST)?;
    let id = Uuid::new_v4().to_hyphenated().to_string();

    let conn = DB.lock();

    let regres: Result<_> = conn.execute(
        "INSERT INTO accounts (id, username, phash)
                  VALUES (?1, ?2, ?3)",
        params![id, username, phash],
    ).map_err(|_| RegisterError::UsernameTaken.into());
    regres?;

    Ok(())
}

#[derive(Debug, Fail)]
enum MiscError {
    #[fail(display = "UsernameInvalid")]
    UsernameInvalid,
}

pub fn username_to_uuid(username: String) -> Result<Uuid> {
    let conn = DB.lock();
    let mut stmt = wrap_err(conn.prepare("SELECT id, username, phash FROM accounts"))?;
    let account_iter = stmt.query_map(params![], |row| {
        Ok(RawAccount {
            id: row.get(0)?,
            username: row.get(1)?,
            phash: row.get(2)?,
        })
    })?;

    for account in account_iter {
        if let Ok(account) = account {
            if account.username == username {
                return Ok(wrap_err(Uuid::parse_str(&account.id))?);
            }
        }
    }

    Err(MiscError::UsernameInvalid.into())
}
