// ============================================================================
// Password work: the login decision and password hashing, with the two limits
// that keep them from being a lever.
//
//   1. An attempt takes its slot (per address, per username) with an atomic
//      increment BEFORE any hashing. A burst of N concurrent wrong logins is
//      admitted at most MAX_LOGIN_ATTEMPTS times; the rest are turned away
//      without a single Argon2 operation. (It used to read the lock at the
//      start of a request and write it at the end, so all N got through.)
//   2. Argon2 runs on the blocking pool, never on an async worker, behind a
//      semaphore (about one permit per CPU). A request that cannot get a
//      permit within a short wait is answered "busy" (503), not queued.
// ============================================================================
use crate::db;
use crate::security;
use crate::state::{user_throttle_key, AppState, SlotResult};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;
use tracing::error;

#[derive(Debug, PartialEq, Eq)]
pub enum LoginOutcome {
    /// The password was right.
    Success,
    /// Evaluated and wrong (or no such user, or a user without a password): "Invalid credentials".
    BadCredentials,
    /// Over the attempt limit for this address or username; seconds until the window ends. Nothing was hashed.
    Locked(i64),
    /// No Argon2 slot came free in time; try again. The attempt did not count.
    Busy,
}

#[derive(Debug, PartialEq, Eq)]
pub enum HashError {
    Busy,
    Failed,
}

/// Run `f` on the blocking pool while holding an Argon2 permit.
async fn on_blocking_pool<T: Send + 'static>(
    state: &AppState,
    permit: OwnedSemaphorePermit,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let metrics = state.metrics.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit; // released when the hash is done, even if the request that wanted it is gone
        metrics.argon2_runs.fetch_add(1, Ordering::Relaxed);
        f()
    })
    .await
    .map_err(|e| error!("argon2 task failed: {}", e))
    .ok()
}

/// Hash a new password under an Argon2 permit.
pub async fn hash_password(state: &AppState, password: &str) -> Result<String, HashError> {
    let permit = state.acquire_hash_permit().await.ok_or(HashError::Busy)?;
    let password = password.to_owned();
    let hashed = on_blocking_pool(state, permit, move || {
        Argon2::default().hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng)).map(|h| h.to_string())
    })
    .await;
    match hashed {
        Some(Ok(h)) => Ok(h),
        _ => Err(HashError::Failed),
    }
}

/// Decide a password login. `ip` is the client address as a string, already canonical.
pub async fn attempt_login(state: &Arc<AppState>, ip: &str, username: &str, password: &str) -> LoginOutcome {
    let user_key = user_throttle_key(username);

    // 1. The slot, before anything is hashed or compared.
    let slots = match state.take_login_slots(ip, &user_key).await {
        SlotResult::Admitted(s) => s,
        SlotResult::Locked(ttl) => return LoginOutcome::Locked(ttl),
    };

    // A login may name a legacy, non-ASCII username (it is only a bound SQL parameter), but not an absurd one, and
    // no password longer than 256 bytes can exist: refuse without hashing. The slot stays spent: it was a failure.
    if username.len() > security::MAX_LOGIN_USERNAME_BYTES || password.len() > security::MAX_PASSWORD_LENGTH {
        return LoginOutcome::BadCredentials;
    }

    // 2. An Argon2 permit, or "busy" (the attempt is not counted against anyone).
    let stored = db::get_password_hash(&state.pool, username).await;
    let permit = match state.acquire_hash_permit().await {
        Some(p) => p,
        None => {
            state.release_login_slots(slots).await;
            return LoginOutcome::Busy;
        }
    };

    // 3. Verify on the blocking pool. An unknown user (or one without a password) still pays for one hash, so
    //    "no such user" is not faster than "wrong password".
    let password = password.to_owned();
    let ok = on_blocking_pool(state, permit, move || match stored {
        Some(h) => match PasswordHash::new(&h) {
            Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
            Err(_) => false,
        },
        None => {
            let _ = Argon2::default().hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng));
            false
        }
    })
    .await
    .unwrap_or(false);

    if ok {
        state.login_succeeded(slots).await;
        LoginOutcome::Success
    } else {
        LoginOutcome::BadCredentials // the slot taken in step 1 is the failure's record
    }
}

#[cfg(test)]
mod tests;
