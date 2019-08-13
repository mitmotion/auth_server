use crate::util::{wrap_err, Result};
use auth_common::AuthToken;
use bcrypt::{hash, verify, DEFAULT_COST};
use failure::Fail;
use lazy_static::lazy_static;
use parking_lot::Mutex;
use rusqlite::{params, Connection};
use std::net::Ipv4Addr;

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
                  key             TEXT PRIMARY KEY UNIQUE,
                  user_id         TEXT NOT NULL,
                  created_at      TEXT NOT NULL,
                  server          TEXT NOT NULL
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

struct RawToken {
    key: String,
    user_id: String,
    created_at: String,
    server: String,
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

    let regres: Result<_> = conn
        .execute(
            "INSERT INTO accounts (id, username, phash)
                  VALUES (?1, ?2, ?3)",
            params![id, username, phash],
        )
        .map_err(|_| RegisterError::UsernameTaken.into());
    regres?;

    Ok(())
}

#[derive(Debug, Fail)]
enum MiscError {
    #[fail(display = "UsernameInvalid")]
    UsernameInvalid,

    #[fail(display = "UsernameInvalid")]
    UuidInvalid,

    #[fail(display = "InvalidPassword")]
    InvalidPassword,

    #[fail(display = "InvalidToken")]
    InvalidToken,
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

fn uuid_to_phash(id: Uuid) -> Result<String> {
    let id = id.to_hyphenated().to_string();
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
            if account.id == id {
                return Ok(account.phash);
            }
        }
    }

    Err(MiscError::UuidInvalid.into())
}

pub fn generate_token(id: Uuid, password: String, server: Ipv4Addr) -> Result<AuthToken> {
    let phash = uuid_to_phash(id.clone())?;
    if verify(password, &phash)? {
        let token = AuthToken::generate();
        let key = token.serialize();
        let user_id = id.to_hyphenated().to_string();
        let created_at = time::get_time().sec.to_string();
        let server = server.to_string();
        let conn = DB.lock();
        wrap_err(conn.execute(
            "INSERT INTO keys (key, user_id, created_at, server)
                      VALUES (?1, ?2, ?3, ?4)",
            params![key, user_id, created_at, server],
        ))?;
        Ok(token)
    } else {
        Err(MiscError::InvalidPassword.into())
    }
}

pub fn verify_token(client: Ipv4Addr, token: AuthToken) -> Result<Uuid> {
    let addr = client.to_string();
    let conn = DB.lock();
    let mut stmt = wrap_err(conn.prepare("SELECT key, user_id, created_at, server FROM keys"))?;
    let token_iter = stmt.query_map(params![], |row| {
        Ok(RawToken {
            key: row.get(0)?,
            user_id: row.get(1)?,
            created_at: row.get(2)?,
            server: row.get(3)?,
        })
    })?;

    for t1 in token_iter {
        if let Ok(t1) = t1 {
            if t1.key.parse() == Ok(token.unique) {
                let t1time = t1.created_at.parse::<u64>()?;
                let currenttime = time::get_time().sec as u64;
                let diff = currenttime - t1time;
                if diff < 15 && addr == t1.server {
                    // token is valid
                    wrap_err(conn.execute("DELETE FROM keys WHERE key = ?1", params![t1.key]))?;
                    return Ok(wrap_err(Uuid::parse_str(&t1.user_id))?);
                }
            }
        }
    }

    Err(MiscError::InvalidToken.into())
}
