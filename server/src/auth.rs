use crate::cache::TimedCache;
use argon2::Error as HashError;
use auth_common::AuthToken;
use lazy_static::lazy_static;
use rusqlite::{params, Connection, Error as DbError, NO_PARAMS};
use serde_json::Error as JsonError;
use std::error::Error;
use std::fmt;
use std::ops::Deref;
use uuid::Uuid;

lazy_static! {
    static ref TOKENS: TimedCache = TimedCache::new();
}

fn db() -> Result<Connection, AuthError> {
    Ok(Connection::open("/opt/veloren-auth/data/auth.db")?)
}

fn salt() -> [u8; 16] {
    rand::random::<u128>().to_le_bytes()
}

fn decapitalize(string: &str) -> LowercaseString {
    LowercaseString(string.chars().flat_map(char::to_lowercase).collect())
}

struct LowercaseString(String);
impl Deref for LowercaseString {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub enum AuthError {
    UserExists,
    UserDoesNotExist,
    InvalidLogin,
    InvalidToken,
    Db(DbError),
    Hash(HashError),
    Json(JsonError),
    InvalidRequest(String),
    RateLimit,
}

impl AuthError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::UserExists => 400,
            Self::UserDoesNotExist => 400,
            Self::InvalidLogin => 400,
            Self::InvalidToken => 400,
            Self::Db(_) => 500,
            Self::Hash(_) => 500,
            Self::Json(_) => 400,
            Self::InvalidRequest(_) => 400,
            Self::RateLimit => 429,
        }
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::UserExists => "That username is already taken.".into(),
                Self::UserDoesNotExist => "That user does not exist.".into(),
                Self::InvalidLogin =>
                    "The username + password combination was incorrect or the user does not exist."
                        .into(),
                Self::InvalidToken => "The given token is invalid.".into(),
                Self::Db(err) => format!("Database error: {}", err),
                Self::Hash(err) => format!("Error securely storing password: {}", err),
                Self::Json(err) => format!("Error decoding JSON: {}", err),
                Self::InvalidRequest(s) =>
                    format!("The request was invalid in some form. Reason: {}", s),
                Self::RateLimit => "You are sending too many requests. Please slow down.".into(),
            }
        )
    }
}

impl Error for AuthError {}

impl From<DbError> for AuthError {
    fn from(err: DbError) -> Self {
        Self::Db(err)
    }
}

impl From<HashError> for AuthError {
    fn from(err: HashError) -> Self {
        Self::Hash(err)
    }
}

impl From<JsonError> for AuthError {
    fn from(err: JsonError) -> Self {
        Self::Json(err)
    }
}

pub fn init_db() -> Result<(), AuthError> {
    db()?.execute(
        "
        CREATE TABLE IF NOT EXISTS users (
            uuid TEXT NOT NULL PRIMARY KEY,
            username_lowercase TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            pwhash TEXT NOT NULL
        )
    ",
        NO_PARAMS,
    )?;
    Ok(())
}

fn user_exists(username_lowercase: &LowercaseString) -> Result<bool, AuthError> {
    let db = db()?;
    let mut stmt = db.prepare("SELECT uuid FROM users WHERE username_lowercase == ?1")?;
    Ok(stmt.exists(params![username_lowercase.deref()])?)
}

pub fn username_to_uuid(username: &str) -> Result<Uuid, AuthError> {
    let username_lowercase = decapitalize(username);
    let db = db()?;
    let mut stmt = db.prepare_cached("SELECT uuid FROM users WHERE username_lowercase == ?1")?;
    let result = stmt
        .query_map(params![username_lowercase.deref()], |row| {
            row.get::<_, String>(0)
        })?
        .filter_map(|s| s.ok())
        .filter_map(|s| Uuid::parse_str(&s).ok())
        .next()
        .ok_or(AuthError::UserDoesNotExist);
    result
}

pub fn uuid_to_username(uuid: &Uuid) -> Result<String, AuthError> {
    let db = db()?;
    let uuid = uuid.to_simple().to_string();
    let mut stmt = db.prepare_cached("SELECT username FROM users WHERE uuid == ?1")?;
    let result = stmt
        .query_map(params![uuid], |row| row.get::<_, String>(0))?
        .filter_map(|s| s.ok())
        .next()
        .ok_or(AuthError::UserDoesNotExist);
    result
}

pub fn register(username: &str, password: &str) -> Result<(), AuthError> {
    let username_lowercase = decapitalize(username);
    if user_exists(&username_lowercase)? {
        return Err(AuthError::UserExists);
    }
    let uuid = Uuid::new_v4().to_simple().to_string();
    let hconfig = argon2::Config::default();
    let pwhash = argon2::hash_encoded(password.as_bytes(), &salt(), &hconfig)?;
    db()?.execute(
        "INSERT INTO users (uuid, username_lowercase, username, pwhash) VALUES(?1, ?2, ?3, ?4)",
        params![uuid, username_lowercase.deref(), username, pwhash],
    )?;
    Ok(())
}

/// Checks if the password is correct and that the user exists.
fn is_valid(username_lowercase: &LowercaseString, password: &str) -> Result<bool, AuthError> {
    let db = db()?;
    let mut stmt = db.prepare_cached("SELECT pwhash FROM users WHERE username_lowercase == ?1")?;
    let result = stmt
        .query_map(params![&username_lowercase.deref()], |row| {
            row.get::<_, String>(0)
        })?
        .filter_map(|s| s.ok())
        .filter_map(|correct| argon2::verify_encoded(&correct, password.as_bytes()).ok())
        .next()
        .ok_or(AuthError::InvalidLogin);
    result
}

pub fn generate_token(username: &str, password: &str) -> Result<AuthToken, AuthError> {
    let username_lowercase = decapitalize(username);
    if !is_valid(&username_lowercase, password)? {
        return Err(AuthError::InvalidLogin);
    }

    let uuid = username_to_uuid(&username_lowercase)?;
    let token = AuthToken::generate();
    TOKENS.insert(token, uuid);
    Ok(token)
}

pub fn verify(token: AuthToken) -> Result<Uuid, AuthError> {
    let mut uuid = None;
    TOKENS.run(&token, |entry| {
        uuid = entry.map(|e| e.data.clone());
        false
    });
    uuid.ok_or(AuthError::InvalidToken)
}
