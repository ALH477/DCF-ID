// ============================================================================
// SQLite: schema, and every query that reads or writes the users table outside
// billing. Rows are read with `try_get` and a missing or mistyped column is an
// error the caller handles -- never a panic (release builds abort on one).
// ============================================================================
use crate::security::{sanitize_discord_username, username_with_suffix};
use chrono::Utc;
use sqlx::{sqlite::SqlitePool, Row};
use tracing::{error, warn};

/// What `init` found out about the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaReport {
    /// The case-insensitive unique index on `username` exists. False means the table
    /// already held names that differ only in case; uniqueness is then enforced in the
    /// INSERT itself (see `register_user`).
    pub username_nocase_unique: bool,
}

pub async fn init(pool: &SqlitePool) -> Result<SchemaReport, sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT,
            access_token TEXT UNIQUE NOT NULL,
            discord_id TEXT UNIQUE,
            data_used INTEGER DEFAULT 0,
            account_balance REAL DEFAULT 0.00,
            last_reset_date TEXT DEFAULT '',
            last_ip TEXT,
            last_seen TEXT,
            created_at TEXT,
            is_vip INTEGER DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_discord ON users(discord_id)").execute(pool).await.ok();
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_token ON users(access_token)").execute(pool).await.ok();

    // Stripe event ids already credited: a retry or a replay inside the signature
    // tolerance must not credit twice. session_id is UNIQUE as well, so two different
    // events for one checkout session still credit once.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS stripe_events (
            id TEXT PRIMARY KEY,
            session_id TEXT UNIQUE,
            user_id INTEGER,
            amount_cents INTEGER NOT NULL,
            processed_at TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    let username_nocase_unique = match sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase ON users(username COLLATE NOCASE)",
    )
    .execute(pool)
    .await
    {
        Ok(_) => true,
        Err(e) => {
            warn!(
                event = "username_nocase_index_failed",
                error = %e,
                "existing usernames collide when case is ignored; new registrations are still checked \
                 case-insensitively in the INSERT, but the database cannot enforce it"
            );
            false
        }
    };
    Ok(SchemaReport { username_nocase_unique })
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq)]
pub struct UserRow {
    pub username: String,
    pub access_token: String,
    pub data_used: i64,
    pub account_balance: f64,
    pub is_vip: bool,
}

pub async fn get_user_by_username(pool: &SqlitePool, username: &str) -> Option<UserRow> {
    let row = sqlx::query(
        "SELECT username, access_token, data_used, account_balance, is_vip FROM users WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_err(|e| error!("get_user_by_username: {}", e))
    .ok()??;
    let parse = || -> Result<UserRow, sqlx::Error> {
        Ok(UserRow {
            username: row.try_get("username")?,
            access_token: row.try_get("access_token")?,
            data_used: row.try_get::<Option<i64>, _>("data_used")?.unwrap_or(0),
            account_balance: row.try_get::<Option<f64>, _>("account_balance")?.unwrap_or(0.0),
            is_vip: row.try_get::<Option<i64>, _>("is_vip")?.unwrap_or(0) == 1,
        })
    };
    parse().map_err(|e| error!("get_user_by_username: bad row for a user: {}", e)).ok()
}

/// The row id of a user: what Stripe checkout metadata carries instead of the secret access token.
pub async fn get_user_id(pool: &SqlitePool, username: &str) -> Option<i64> {
    let row = sqlx::query("SELECT id FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await
        .map_err(|e| error!("get_user_id: {}", e))
        .ok()??;
    row.try_get("id").ok()
}

/// The stored password hash, or None for no such user, a user without a password
/// (created through Discord), or an unreadable row.
pub async fn get_password_hash(pool: &SqlitePool, username: &str) -> Option<String> {
    let row = sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await
        .map_err(|e| error!("get_password_hash: {}", e))
        .ok()??;
    match row.try_get::<Option<String>, _>("password_hash") {
        Ok(Some(h)) if !h.is_empty() => Some(h),
        Ok(_) => None,
        Err(e) => {
            error!("get_password_hash: bad row: {}", e);
            None
        }
    }
}

/// `ip` is None when the client address was not admitted for storage; then nothing is written
/// except `last_seen`.
pub async fn update_user_ip(pool: &SqlitePool, username: &str, ip: Option<&str>) {
    let now = Utc::now().to_rfc3339();
    let _ = match ip {
        Some(ip) => {
            sqlx::query("UPDATE users SET last_ip = ?, last_seen = ? WHERE username = ?")
                .bind(ip)
                .bind(&now)
                .bind(username)
                .execute(pool)
                .await
        }
        None => sqlx::query("UPDATE users SET last_seen = ? WHERE username = ?").bind(&now).bind(username).execute(pool).await,
    };
}

// ---------------------------------------------------------------------------
// Account creation
// ---------------------------------------------------------------------------
#[derive(Debug)]
pub enum RegisterError {
    /// Another account has this name, ignoring ASCII case.
    Taken,
    Db(sqlx::Error),
}

fn is_unique_violation(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(d) => d.message().contains("UNIQUE"),
        _ => false,
    }
}

/// Create a password account. The NOT EXISTS makes the case-insensitive check part of the
/// INSERT, so it holds even where the unique NOCASE index could not be built.
pub async fn register_user(
    pool: &SqlitePool,
    username: &str,
    password_hash: &str,
    access_token: &str,
    ip: Option<&str>,
) -> Result<(), RegisterError> {
    let now = Utc::now();
    let res = sqlx::query(
        "INSERT INTO users (username, password_hash, access_token, data_used, account_balance,
                            last_reset_date, is_vip, last_ip, last_seen, created_at)
         SELECT ?1, ?2, ?3, 0, 0.0, ?4, 0, ?5, ?6, ?6
         WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = ?1 COLLATE NOCASE)",
    )
    .bind(username)
    .bind(password_hash)
    .bind(access_token)
    .bind(now.format("%Y-%m").to_string())
    .bind(ip.map(|s| s.to_string()))
    .bind(now.to_rfc3339())
    .execute(pool)
    .await;
    match res {
        Ok(r) if r.rows_affected() == 1 => Ok(()),
        Ok(_) => Err(RegisterError::Taken),
        Err(e) if is_unique_violation(&e) => Err(RegisterError::Taken),
        Err(e) => Err(RegisterError::Db(e)),
    }
}

#[derive(Debug)]
pub enum DiscordUserError {
    Exhausted,
    Db(sqlx::Error),
}

async fn username_for_discord_id(pool: &SqlitePool, discord_id: &str) -> Result<Option<String>, sqlx::Error> {
    match sqlx::query("SELECT username FROM users WHERE discord_id = ?").bind(discord_id).fetch_optional(pool).await? {
        Some(row) => Ok(Some(row.try_get("username")?)),
        None => Ok(None),
    }
}

/// The username of the account linked to this Discord id, creating one if there is none.
/// The Discord-supplied name is cut down to the allowed characters first (fallback
/// `discord_<id>`), then suffixed `_1`, `_2`, ... within 32 bytes until it is free ignoring case.
pub async fn find_or_create_discord_user(
    pool: &SqlitePool,
    discord_id: &str,
    raw_name: &str,
    access_token: &str,
    ip: Option<&str>,
) -> Result<(String, bool), DiscordUserError> {
    if let Some(u) = username_for_discord_id(pool, discord_id).await.map_err(DiscordUserError::Db)? {
        return Ok((u, false));
    }
    let base = sanitize_discord_username(raw_name, discord_id);
    let now = Utc::now();
    for attempt in 0..=100u32 {
        let candidate = username_with_suffix(&base, attempt);
        let res = sqlx::query(
            "INSERT INTO users (username, discord_id, access_token, data_used, account_balance,
                                last_reset_date, is_vip, last_ip, last_seen, created_at)
             SELECT ?1, ?2, ?3, 0, 0.0, ?4, 0, ?5, ?6, ?6
             WHERE NOT EXISTS (SELECT 1 FROM users WHERE username = ?1 COLLATE NOCASE)",
        )
        .bind(&candidate)
        .bind(discord_id)
        .bind(access_token)
        .bind(now.format("%Y-%m").to_string())
        .bind(ip.map(|s| s.to_string()))
        .bind(now.to_rfc3339())
        .execute(pool)
        .await;
        match res {
            Ok(r) if r.rows_affected() == 1 => return Ok((candidate, true)),
            Ok(_) => continue, // the name is taken (ignoring case): next suffix
            Err(e) if is_unique_violation(&e) => {
                // either the name raced us, or this Discord id was linked meanwhile
                if let Some(u) = username_for_discord_id(pool, discord_id).await.map_err(DiscordUserError::Db)? {
                    return Ok((u, false));
                }
                continue;
            }
            Err(e) => return Err(DiscordUserError::Db(e)),
        }
    }
    Err(DiscordUserError::Exhausted)
}

#[cfg(test)]
pub(crate) mod testutil {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use sqlx::SqlitePool;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    /// A fresh on-disk database (a file, so that several pool connections see the same data
    /// and writers genuinely contend) with the schema applied. The file goes away with `TempDb`.
    pub struct TempDb {
        pub pool: SqlitePool,
        pub path: std::path::PathBuf,
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let _ = std::fs::remove_file(format!("{}{}", self.path.display(), suffix));
            }
        }
    }

    pub async fn temp_db() -> TempDb {
        let path = std::env::temp_dir().join(format!(
            "dcfid-test-{}-{}-{}.db",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos()
        ));
        let opts = SqliteConnectOptions::from_str(&format!("sqlite:{}?mode=rwc", path.display())).unwrap();
        let pool = SqlitePoolOptions::new().max_connections(10).connect_with(opts).await.unwrap();
        super::init(&pool).await.unwrap();
        TempDb { pool, path }
    }

    pub async fn seed(pool: &SqlitePool, username: &str, token: &str, used: i64, balance: f64, vip: bool) {
        sqlx::query(
            "INSERT INTO users (username, access_token, data_used, account_balance, is_vip, created_at)
             VALUES (?, ?, ?, ?, ?, '2026-01-01T00:00:00Z')",
        )
        .bind(username)
        .bind(token)
        .bind(used)
        .bind(balance)
        .bind(vip as i64)
        .execute(pool)
        .await
        .unwrap();
    }

    pub async fn balance(pool: &SqlitePool, token: &str) -> f64 {
        sqlx::query_scalar("SELECT account_balance FROM users WHERE access_token = ?").bind(token).fetch_one(pool).await.unwrap()
    }

    pub async fn used(pool: &SqlitePool, token: &str) -> i64 {
        sqlx::query_scalar("SELECT data_used FROM users WHERE access_token = ?").bind(token).fetch_one(pool).await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    const TOK: &str = "abcdefghijklmnopqrstuvwxyzABCDEF";

    #[tokio::test]
    async fn null_and_empty_password_hash_is_none_not_a_panic() {
        let db = temp_db().await;
        sqlx::query("INSERT INTO users (username, access_token, discord_id) VALUES ('discorduser', ?, '1')")
            .bind(TOK)
            .execute(&db.pool)
            .await
            .unwrap();
        assert_eq!(get_password_hash(&db.pool, "discorduser").await, None);
        assert_eq!(get_password_hash(&db.pool, "nobody").await, None);
        sqlx::query("UPDATE users SET password_hash = '' WHERE username = 'discorduser'").execute(&db.pool).await.unwrap();
        assert_eq!(get_password_hash(&db.pool, "discorduser").await, None);
    }

    #[tokio::test]
    async fn mistyped_columns_are_errors_not_panics() {
        let db = temp_db().await;
        seed(&db.pool, "typeconf", TOK, 5, 1.0, false).await;
        for col in ["is_vip", "data_used", "account_balance"] {
            sqlx::query(&format!("UPDATE users SET {col} = 'garbage' WHERE username = 'typeconf'")).execute(&db.pool).await.unwrap();
            // must return, one way or the other; a panic here fails the test
            let _ = get_user_by_username(&db.pool, "typeconf").await;
        }
        // TEXT affinity would turn 12345 into '12345'; a BLOB stays a BLOB and is not a String
        sqlx::query("UPDATE users SET password_hash = x'00ff' WHERE username = 'typeconf'").execute(&db.pool).await.unwrap();
        assert_eq!(get_password_hash(&db.pool, "typeconf").await, None);
        sqlx::query("UPDATE users SET username = x'00ff' WHERE access_token = ?").bind(TOK).execute(&db.pool).await.unwrap();
        let _ = get_user_by_username(&db.pool, "typeconf").await;
    }

    #[tokio::test]
    async fn null_numeric_columns_read_as_zero() {
        let db = temp_db().await;
        seed(&db.pool, "nulls", TOK, 5, 1.0, false).await;
        sqlx::query("UPDATE users SET data_used = NULL, account_balance = NULL, is_vip = NULL").execute(&db.pool).await.unwrap();
        let u = get_user_by_username(&db.pool, "nulls").await.unwrap();
        assert_eq!((u.data_used, u.account_balance, u.is_vip), (0, 0.0, false));
    }

    #[tokio::test]
    async fn usernames_are_unique_ignoring_case() {
        let db = temp_db().await;
        register_user(&db.pool, "Alice99", "hash", TOK, Some("1.2.3.4")).await.unwrap();
        for dup in ["alice99", "ALICE99", "aLiCe99", "Alice99"] {
            let tok = format!("{:0<32}", dup.len());
            assert!(matches!(register_user(&db.pool, dup, "h", &tok, None).await, Err(RegisterError::Taken)), "{dup}");
        }
        register_user(&db.pool, "alice98", "hash", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", None).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users").fetch_one(&db.pool).await.unwrap();
        assert_eq!(n, 2);
    }

    #[tokio::test]
    async fn case_insensitive_uniqueness_survives_legacy_duplicates() {
        // a database from before this change: two names that differ only in case, no NOCASE index
        let path = std::env::temp_dir().join(format!("dcfid-legacy-{}.db", std::process::id()));
        let opts = sqlx::sqlite::SqliteConnectOptions::new().filename(&path).create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new().max_connections(2).connect_with(opts).await.unwrap();
        sqlx::query("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT,
                     access_token TEXT UNIQUE NOT NULL, discord_id TEXT UNIQUE, data_used INTEGER DEFAULT 0,
                     account_balance REAL DEFAULT 0.00, last_reset_date TEXT DEFAULT '', last_ip TEXT, last_seen TEXT,
                     created_at TEXT, is_vip INTEGER DEFAULT 0)").execute(&pool).await.unwrap();
        seed(&pool, "Bob", "b1111111111111111111111111111111", 0, 0.0, false).await;
        seed(&pool, "bob", "b2222222222222222222222222222222", 0, 0.0, false).await;
        let report = init(&pool).await.unwrap();
        assert!(!report.username_nocase_unique, "the index cannot be built over those rows");
        // the index failure is survivable: the INSERT still refuses a third spelling
        assert!(matches!(
            register_user(&pool, "BOB", "h", "b3333333333333333333333333333333", None).await,
            Err(RegisterError::Taken)
        ));
        // and the legacy users can still be found by their exact names
        assert!(get_user_by_username(&pool, "Bob").await.is_some());
        assert!(get_user_by_username(&pool, "bob").await.is_some());
        // a non-ASCII legacy username is readable (login stays possible); it just cannot be registered anew
        seed(&pool, "\u{430}dmin", "b4444444444444444444444444444444", 0, 0.0, false).await;
        assert!(get_user_by_username(&pool, "\u{430}dmin").await.is_some());
        pool.close().await;
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(format!("{}{}", path.display(), suffix));
        }
    }

    #[tokio::test]
    async fn discord_users_get_gate_clean_unique_names() {
        let db = temp_db().await;
        let (u1, new1) = find_or_create_discord_user(&db.pool, "1001", "Alice", "t1111111111111111111111111111111", Some("1.2.3.4")).await.unwrap();
        assert_eq!((u1.as_str(), new1), ("Alice", true));
        // the same Discord id again: the same account, nothing created
        let (u1b, new1b) = find_or_create_discord_user(&db.pool, "1001", "Other", "t9999999999999999999999999999999", None).await.unwrap();
        assert_eq!((u1b.as_str(), new1b), ("Alice", false));
        // another Discord user with the same name, differing in case: suffixed
        let (u2, _) = find_or_create_discord_user(&db.pool, "1002", "alice", "t2222222222222222222222222222222", None).await.unwrap();
        assert_eq!(u2, "alice_1");
        let (u3, _) = find_or_create_discord_user(&db.pool, "1003", "ALICE", "t3333333333333333333333333333333", None).await.unwrap();
        assert_eq!(u3, "ALICE_2");
        // a name of nothing but characters outside the set: the fallback
        let (u4, _) = find_or_create_discord_user(&db.pool, "1004", "名前です", "t4444444444444444444444444444444", None).await.unwrap();
        assert_eq!(u4, "discord_1004");
        // a 32-byte name collides: the suffix still fits 32 bytes
        let long = "x".repeat(40);
        let (u5, _) = find_or_create_discord_user(&db.pool, "1005", &long, "t5555555555555555555555555555555", None).await.unwrap();
        let (u6, _) = find_or_create_discord_user(&db.pool, "1006", &long, "t6666666666666666666666666666666", None).await.unwrap();
        assert_eq!(u5, "x".repeat(32));
        assert_eq!(u6, format!("{}_1", "x".repeat(30)));
        for u in [&u1, &u2, &u3, &u4, &u5, &u6] {
            assert!(crate::gate::admitte_nomen(u).is_ok(), "{u}");
        }
    }

    #[tokio::test]
    async fn concurrent_registrations_of_one_name_create_one_account() {
        let db = temp_db().await;
        let mut handles = vec![];
        for i in 0..20u32 {
            let pool = db.pool.clone();
            handles.push(tokio::spawn(async move {
                let name = if i % 2 == 0 { "Racer" } else { "racer" };
                let tok = format!("{:0>32}", i);
                register_user(&pool, name, "h", &tok, None).await.is_ok()
            }));
        }
        let mut won = 0;
        for h in handles {
            won += h.await.unwrap() as u32;
        }
        assert_eq!(won, 1);
    }

    #[tokio::test]
    async fn the_stored_ip_is_only_written_when_given() {
        let db = temp_db().await;
        register_user(&db.pool, "ipuser", "h", TOK, Some("1.2.3.4")).await.unwrap();
        update_user_ip(&db.pool, "ipuser", None).await;
        let ip: Option<String> = sqlx::query_scalar("SELECT last_ip FROM users WHERE username='ipuser'").fetch_one(&db.pool).await.unwrap();
        assert_eq!(ip.as_deref(), Some("1.2.3.4"));
        update_user_ip(&db.pool, "ipuser", Some("5.6.7.8")).await;
        let ip: Option<String> = sqlx::query_scalar("SELECT last_ip FROM users WHERE username='ipuser'").fetch_one(&db.pool).await.unwrap();
        assert_eq!(ip.as_deref(), Some("5.6.7.8"));
    }
}
