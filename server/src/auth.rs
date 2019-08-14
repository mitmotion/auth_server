use crate::util::{wrap_err, Result};
use auth_common::AuthToken;
use bcrypt::{hash, verify};
use failure::Fail;
use lazy_static::lazy_static;
use r2d2_postgres::{PostgresConnectionManager, TlsMode};
use std::env;
use std::net::Ipv4Addr;
use uuid::Uuid;

fn db_host() -> String {
    env::var("DB_PROVIDER").unwrap_or("localhost".to_string())
}

lazy_static! {
    static ref DB: r2d2::Pool<PostgresConnectionManager> = {
        let dsn = format!("postgres://postgres:supersecret1337@{}", db_host());
        let manager = PostgresConnectionManager::new(dsn.as_str(), TlsMode::None)
            .expect("failed to create manager");
        r2d2::Pool::builder()
            .max_size(16)
            .build(manager)
            .expect("failed to create pool")
    };
}

pub fn prepare_db() -> Result<()> {
    let conn = DB.get().unwrap();

    wrap_err(conn.execute(
        "CREATE TABLE IF NOT EXISTS accounts (
                  id              VARCHAR PRIMARY KEY UNIQUE,
                  username        VARCHAR NOT NULL UNIQUE,
                  phash           VARCHAR NOT NULL
        )",
        &[],
    ))?;

    wrap_err(conn.execute(
        "CREATE TABLE IF NOT EXISTS keys (
                  key             VARCHAR PRIMARY KEY UNIQUE,
                  user_id         VARCHAR NOT NULL,
                  created_at      VARCHAR NOT NULL,
                  server          VARCHAR NOT NULL
        )",
        &[],
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
    let phash = hash(password, 4)?;
    let id = Uuid::new_v4().to_hyphenated().to_string();

    let conn = DB.get().unwrap();

    let regres: Result<_> = conn
        .execute(
            "INSERT INTO accounts (id, username, phash)
                  VALUES ($1, $2, $3)",
            &[&id, &username, &phash],
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
    let conn = DB.get().unwrap();

    let query = conn.query("SELECT (id, username, phash) FROM accounts", &[])?;

    for row in &query {
        let account = RawAccount {
            id: row.get(0),
            username: row.get(1),
            phash: row.get(2),
        };

        if account.username == username {
            return Ok(wrap_err(Uuid::parse_str(&account.id))?);
        }
    }

    Err(MiscError::UsernameInvalid.into())
}

fn uuid_to_phash(id: Uuid) -> Result<String> {
    let id = id.to_hyphenated().to_string();
    let conn = DB.get().unwrap();
    let query = conn.query("SELECT (id, username, phash) FROM accounts", &[])?;
    for row in &query {
        let account = RawAccount {
            id: row.get(0),
            username: row.get(1),
            phash: row.get(2),
        };

        if account.id == id {
            return Ok(account.phash);
        }
    }

    Err(MiscError::UuidInvalid.into())
}

pub fn generate_token(username: String, password: String, server: Ipv4Addr) -> Result<AuthToken> {
    let id = username_to_uuid(username)?;
    let phash = uuid_to_phash(id.clone())?;
    if verify(password, &phash)? {
        let token = AuthToken::generate();
        let key = token.serialize();
        let user_id = id.to_hyphenated().to_string();
        let created_at = time::get_time().sec.to_string();
        let server = server.to_string();
        let conn = DB.get().unwrap();
        wrap_err(conn.execute(
            "INSERT INTO keys (key, user_id, created_at, server)
                      VALUES ($1, $2, $3, $4)",
            &[&key, &user_id, &created_at, &server],
        ))?;
        Ok(token)
    } else {
        Err(MiscError::InvalidPassword.into())
    }
}

pub fn verify_token(client: Ipv4Addr, token: AuthToken) -> Result<Uuid> {
    let addr = client.to_string();
    let conn = DB.get().unwrap();
    let query = conn.query("SELECT (key, user_id, created_at, server) FROM keys", &[])?;

    for row in &query {
        let t1 = RawToken {
            key: row.get(0),
            user_id: row.get(1),
            created_at: row.get(2),
            server: row.get(3),
        };

        if t1.key.parse() == Ok(token.unique) {
            let t1time = t1.created_at.parse::<u64>()?;
            let currenttime = time::get_time().sec as u64;
            let diff = currenttime - t1time;
            if diff < 15 && addr == t1.server {
                // token is valid
                wrap_err(conn.execute("DELETE FROM keys WHERE key = $1", &[&t1.key]))?;
                return Ok(wrap_err(Uuid::parse_str(&t1.user_id))?);
            }
        }
    }

    Err(MiscError::InvalidToken.into())
}
