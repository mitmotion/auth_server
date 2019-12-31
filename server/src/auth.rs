use rusqlite::{Connection, NO_PARAMS, params, Error as DbError};
use uuid::Uuid;
use argon2::Error as HashError;

fn db() -> Result<Connection, AuthError> {
    Ok(Connection::open("/auth.db")?)
}

fn salt() -> [u8; 16] {
    rand::random::<u128>().to_le_bytes()
}

pub enum AuthError {
    UserExists,
    UserDoesNotExist,
    Db(DbError),
    Hash(HashError),
}

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

pub fn init_db() -> Result<(), AuthError> {
    db()?.execute("
        CREATE TABLE IF NOT EXISTS users (
            uuid TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            pwhash TEXT NOT NULL
        )
    ", NO_PARAMS)?;
    Ok(())
}

fn user_exists(username: &str) -> Result<bool, AuthError> {
    let db = db()?;
    let mut stmt = db.prepare("SELECT uuid, username, pwhash FROM users WHERE username == ?1")?;
    Ok(stmt.query_map(params![username], |_| Ok(())).unwrap().count() == 1)
}

pub fn username_to_uuid(username: &str) -> Result<Uuid, AuthError> {
    let db = db()?;
    let mut stmt = db.prepare("SELECT uuid, username, pwhash FROM users WHERE username == ?1")?;
    let result = stmt.query_map(params![username], |row| row.get::<_, String>("uuid"))?.filter_map(|s| s.ok()).filter_map(|s| Uuid::parse_str(&s).ok()).next().ok_or(AuthError::UserDoesNotExist);
    result
}

pub fn register(username: &str, password: &str) -> Result<(), AuthError> {
    if user_exists(username)? { return Err(AuthError::UserExists) }
    let uuid = Uuid::new_v4().to_simple().to_string();
    let hconfig = argon2::Config::default();
    let pwhash = argon2::hash_encoded(password.as_bytes(), &salt(), &hconfig)?;
    db()?.execute("INSERT INTO users (uuid, username, pwhash) VALUES(?1, ?2, ?2)", params![uuid, username, pwhash])?;
    Ok(())
}
