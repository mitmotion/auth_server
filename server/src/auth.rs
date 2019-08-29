use crate::cache::ExpiryCache;
use crate::util::{hash, verify, wrap_err, Result};
use auth_common::AuthToken;
use failure::Fail;
use lazy_static::lazy_static;
use r2d2_postgres::{PostgresConnectionManager, TlsMode};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::Ipv4Addr;
use uuid::Uuid;

const MAX_USERNAME_LEN: usize = 16;
const MAX_EMAIL_LEN: usize = 256;
const MAX_PASSWORD_LEN: usize = 256;
const CONN_POOL_SIZE: u32 = 64;

#[derive(Debug, Fail)]
enum StringValidateError {
    #[fail(display = "LengthExceeded")]
    LengthExceeded,

    #[fail(display = "InvalidText")]
    InvalidText,

    #[fail(display = "InvalidEmail")]
    InvalidEmail,
}

fn ensure_within_len(s: String, l: usize) -> Result<String> {
    if s.len() > l {
        Err(StringValidateError::LengthExceeded.into())
    } else {
        Ok(s)
    }
}

fn ensure_valid_text(s: String) -> Result<String> {
    let text_re = Regex::new(r#"^[[:word:]]*$"#).unwrap();
    if text_re.is_match(&s) {
        Ok(s)
    } else {
        Err(StringValidateError::InvalidText.into())
    }
}

fn ensure_valid_email(s: String) -> Result<String> {
    let email_re = Regex::new(r#"^(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])$"#).unwrap();
    if email_re.is_match(&s) {
        Ok(s)
    } else {
        Err(StringValidateError::InvalidEmail.into())
    }
}

fn db_host() -> String {
    env::var("DB_PROVIDER").unwrap_or_else(|_| "localhost".to_string())
}

lazy_static! {
    static ref DB: r2d2::Pool<PostgresConnectionManager> = {
        let dsn = format!("postgres://postgres:supersecret1337@{}", db_host());
        let manager = PostgresConnectionManager::new(dsn.as_str(), TlsMode::None)
            .expect("failed to create manager");
        r2d2::Pool::builder()
            .max_size(CONN_POOL_SIZE)
            .build(manager)
            .expect("failed to create pool")
    };
    static ref CACHE: ExpiryCache<Vec<u8>, Vec<u8>> = ExpiryCache::new();
}

pub fn prepare_db() -> Result<()> {
    let conn = DB.get().unwrap();

    wrap_err(conn.execute(
        "CREATE TABLE IF NOT EXISTS accounts (
                  id              VARCHAR PRIMARY KEY UNIQUE,
                  email           VARCHAR NOT NULL UNIQUE,
                  username        VARCHAR NOT NULL UNIQUE,
                  phash           VARCHAR NOT NULL
        )",
        &[],
    ))?;

    Ok(())
}

struct RawAccount {
    id: String,
    email: String,
    username: String,
    phash: String,
}

#[derive(Serialize, Deserialize)]
struct TokenData {
    user_id: Uuid,
    server: String,
}

#[derive(Debug, Fail)]
enum RegisterError {
    #[fail(display = "UsernameTaken")]
    UsernameTaken,
}

pub fn register(username: String, email: String, password: String) -> Result<()> {
    let username = ensure_within_len(username, MAX_USERNAME_LEN)?;
    let username = ensure_valid_text(username)?;
    let email = ensure_within_len(email, MAX_EMAIL_LEN)?;
    let email = ensure_valid_email(email)?;
    let password = ensure_within_len(password, MAX_PASSWORD_LEN)?;
    let phash = hash(password.as_bytes());
    let id = Uuid::new_v4().to_hyphenated().to_string();

    let conn = DB.get().unwrap();

    let regres: Result<_> = conn
        .execute(
            "INSERT INTO accounts (id, email, username, phash)
                  VALUES ($1, $2, $3, $4)",
            &[&id, &email, &username, &phash],
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
    let username = ensure_within_len(username, MAX_USERNAME_LEN)?;
    let username = ensure_valid_text(username)?;

    let query = conn.query(
        "SELECT id, email, username, phash FROM accounts WHERE username = '$1'",
        &[&username],
    )?;

    for row in &query {
        let account = RawAccount {
            id: row.get("id"),
            email: row.get("email"),
            username: row.get("username"),
            phash: row.get("phash"),
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
    let query = conn.query(
        "SELECT id, email, username, phash FROM accounts WHERE uuid = '$1'",
        &[&id],
    )?;
    for row in &query {
        let account = RawAccount {
            id: row.get("id"),
            email: row.get("email"),
            username: row.get("username"),
            phash: row.get("phash"),
        };

        if account.id == id {
            return Ok(account.phash);
        }
    }

    Err(MiscError::UuidInvalid.into())
}

pub fn generate_token(username: String, password: String, server: Ipv4Addr) -> Result<AuthToken> {
    let username = ensure_within_len(username, MAX_USERNAME_LEN)?;
    let username = ensure_valid_text(username)?;
    let password = ensure_within_len(password, MAX_PASSWORD_LEN)?;
    let id = username_to_uuid(username)?;
    let phash = uuid_to_phash(id)?;
    if verify(&phash, password.as_bytes()) {
        let token = AuthToken::generate();
        let key = token.serialize();
        let user_id = id;
        let server = server.to_string();
        let tokendata = TokenData { user_id, server };
        let tokendata = bincode::serialize(&tokendata)?;
        CACHE.set(key.into_bytes(), tokendata);
        Ok(token)
    } else {
        Err(MiscError::InvalidPassword.into())
    }
}

pub fn verify_token(client: Ipv4Addr, token: AuthToken) -> Result<Uuid> {
    let addr = client.to_string();
    let key = token.serialize();
    let tokendataraw: Vec<u8> = wrap_err(CACHE.get(&key.into_bytes()))?.1.clone();
    let t1: TokenData = bincode::deserialize(&tokendataraw)?;
    if addr == t1.server {
        // token is valid
        return Ok(t1.user_id);
    } else {
        println!(
            "server from unknown address attempted to verify token, something is up. uaddr = {}",
            addr
        );
    }

    Err(MiscError::InvalidToken.into())
}
