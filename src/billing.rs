// ============================================================================
// Money: usage metering and Stripe credits.
// ============================================================================
use crate::gate;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use sqlx::sqlite::SqlitePool;
use sqlx::Row;
use std::collections::HashMap;
use subtle::ConstantTimeEq;
use tracing::{error, info, warn};

pub const FREE_TIER_BYTES: i64 = 134_217_728; // 128 MB
pub const BYTES_PER_GB: f64 = 1_073_741_824.0;
pub const PRICE_PER_GB: f64 = 0.05;
pub const STRIPE_WEBHOOK_TOLERANCE_SECS: i64 = 300; // 5 minutes

/// The most one usage report may add: 1 TiB. A report is a delta from one game
/// server; anything near the type's range is a bug or an attack.
pub const MAX_REPORT_BYTES: u64 = 1 << 40;
/// The counter never goes above 2^62 bytes; with reports capped at 2^40 the sum
/// cannot reach i64's edge, where SQLite would silently turn an integer into a float.
pub const MAX_DATA_USED: i64 = 1 << 62;

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------
#[derive(Debug)]
pub enum UsageError {
    /// bytes_used above MAX_REPORT_BYTES.
    TooLarge,
    /// No such access token.
    NotFound,
    /// The stored counter is outside +-2^62 (a row damaged by the old overflow bug); not touched.
    OutOfRange,
    Db(sqlx::Error),
}

/// Add `bytes` to a user's usage and bill what falls beyond the free tier, in ONE statement.
///
/// The old handler SELECTed the balance, computed in Rust, and UPDATEd an absolute value: a Stripe
/// credit committed between the two was overwritten. Here every right-hand side is evaluated by
/// SQLite against the row as it stood when the statement took the write lock, so the balance moves
/// by `- cost` and nothing else. VIP accounts are metered and never billed. The balance floors at 0.
pub async fn apply_usage(pool: &SqlitePool, access_token: &str, bytes: u64) -> Result<(), UsageError> {
    if bytes > MAX_REPORT_BYTES {
        return Err(UsageError::TooLarge);
    }
    let b = bytes as i64; // <= 2^40, cannot wrap
    let res = sqlx::query(
        "UPDATE users SET
            data_used = COALESCE(data_used, 0) + ?1,
            account_balance = CASE WHEN COALESCE(is_vip, 0) = 1 THEN account_balance
              ELSE MAX(COALESCE(account_balance, 0.0) -
                   ((CAST(MAX(COALESCE(data_used, 0) + ?1 - ?4, 0) AS REAL)
                     - CAST(MAX(COALESCE(data_used, 0) - ?4, 0) AS REAL)) / ?5 * ?6), 0.0) END,
            last_seen = ?2
         WHERE access_token = ?3
           AND COALESCE(data_used, 0) BETWEEN ?7 AND ?8",
    )
    .bind(b)
    .bind(Utc::now().to_rfc3339())
    .bind(access_token)
    .bind(FREE_TIER_BYTES)
    .bind(BYTES_PER_GB)
    .bind(PRICE_PER_GB)
    .bind(-MAX_DATA_USED)
    .bind(MAX_DATA_USED - b)
    .execute(pool)
    .await
    .map_err(UsageError::Db)?;
    if res.rows_affected() == 1 {
        return Ok(());
    }
    // Zero rows: no such token, or a counter outside the safe range.
    let exists = sqlx::query("SELECT 1 FROM users WHERE access_token = ?")
        .bind(access_token)
        .fetch_optional(pool)
        .await
        .map_err(UsageError::Db)?
        .is_some();
    if exists {
        Err(UsageError::OutOfRange)
    } else {
        Err(UsageError::NotFound)
    }
}

/// The cost in dollars of taking usage from `before` to `after` bytes, by the same arithmetic as
/// the SQL above: what the tests hold the SQL to.
pub fn reference_cost(before: i64, after: i64) -> f64 {
    let billable_before = (before - FREE_TIER_BYTES).max(0) as f64;
    let billable_after = (after - FREE_TIER_BYTES).max(0) as f64;
    (billable_after - billable_before) / BYTES_PER_GB * PRICE_PER_GB
}

// ---------------------------------------------------------------------------
// Stripe signature
// ---------------------------------------------------------------------------
#[derive(Debug, PartialEq, Eq)]
pub enum SignatureError {
    /// The header's shape was refused by the Exsecutor gate (verdict number).
    Shape(u8),
    Stale,
    Mismatch,
    NoSecret,
}

/// Check a `Stripe-Signature` header over `payload` at time `now`.
///
/// The gate has already judged the header's SHAPE (a `t=`, one or more `v1=` of 64 lowercase hex,
/// optional `v0=`, at most 8 items); this parses the values, applies the timestamp tolerance, and
/// compares the HMAC-SHA256 (hmac/sha2 -- nothing cryptographic is reimplemented) against EVERY `v1`
/// entry in constant time. Stripe sends several `v1` while a signing secret is being rotated.
pub fn verify_stripe_signature(payload: &str, header: &str, secret: &str, now: i64) -> Result<(), SignatureError> {
    if secret.is_empty() {
        return Err(SignatureError::NoSecret); // an empty HMAC key is a key anyone has
    }
    if let Err(r) = gate::admitte_formam_signaturae(header) {
        return Err(SignatureError::Shape(match r {
            gate::Refusal::Code(c) => c,
            gate::Refusal::Trapped(_) => 255,
        }));
    }
    let mut timestamp: Option<&str> = None;
    let mut sigs: Vec<&str> = Vec::new();
    for item in header.split(',') {
        if let Some(t) = item.strip_prefix("t=") {
            timestamp = Some(t);
        } else if let Some(v) = item.strip_prefix("v1=") {
            sigs.push(v);
        } // v0= (test mode) is admitted by the gate and ignored here
    }
    let ts_str = timestamp.ok_or(SignatureError::Shape(8))?;
    let ts: i64 = ts_str.parse().map_err(|_| SignatureError::Shape(4))?; // 1..12 digits: cannot fail
    if (now - ts).abs() > STRIPE_WEBHOOK_TOLERANCE_SECS {
        return Err(SignatureError::Stale);
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|_| SignatureError::NoSecret)?;
    mac.update(ts_str.as_bytes());
    mac.update(b".");
    mac.update(payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    // every entry is compared, none short-circuits: how many entries matched is not observable
    let mut ok = subtle::Choice::from(0u8);
    for s in &sigs {
        ok |= expected.as_bytes().ct_eq(s.as_bytes());
    }
    if bool::from(ok) {
        Ok(())
    } else {
        Err(SignatureError::Mismatch)
    }
}

// ---------------------------------------------------------------------------
// Stripe events
// ---------------------------------------------------------------------------
#[derive(Deserialize, Debug)]
pub struct StripeEvent {
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: StripeEventData,
}

#[derive(Deserialize, Debug)]
pub struct StripeEventData {
    pub object: StripeCheckoutSession,
}

#[derive(Deserialize, Debug)]
pub struct StripeCheckoutSession {
    pub id: Option<String>,
    pub amount_total: Option<i64>,
    pub currency: Option<String>,
    pub payment_status: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CreditOutcome {
    /// Credited this many cents to this user id.
    Credited { user_id: i64, cents: u64 },
    /// This event (or its checkout session) was credited before. Nothing changed; answer 200.
    Duplicate,
    /// Recorded, but no account matched; money is held at Stripe and needs a person. Answer 200.
    NoSuchUser { cents: u64 },
    /// Not ours or not payable (no user in the metadata, not "paid", wrong currency, amount out of
    /// bounds, no event id). Nothing changed; answer 200 so Stripe stops retrying.
    Ignored(&'static str),
    /// Ours and paid, but malformed in a way Stripe's own events never are (no checkout session id).
    /// Nothing changed; answer 400 so it shows up as a failed delivery instead of vanishing.
    Rejected(&'static str),
}

fn plausible_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A Checkout Session id: `cs_test_...` / `cs_live_...`.
fn plausible_session_id(s: &str) -> bool {
    s.len() > 3 && s.starts_with("cs_") && plausible_id(s)
}

/// Credit a `checkout.session.completed` event, at most once.
///
/// What is credited is Stripe's own integer `amount_total` (cents), and only when
/// `payment_status` is `paid`; `metadata.amount_dollars` is not read. Which account is credited comes
/// from `metadata.user_id` (the row id), or, for sessions created before this change, from
/// `metadata.access_token`. The idempotency record and the credit are one transaction: if the credit
/// fails nothing is recorded, so Stripe's retry credits it.
pub async fn credit_checkout(pool: &SqlitePool, event: &StripeEvent) -> Result<CreditOutcome, sqlx::Error> {
    let obj = &event.data.object;
    let event_id = match event.id.as_deref() {
        Some(id) if plausible_id(id) => id,
        _ => return Ok(CreditOutcome::Ignored("no usable event id")),
    };
    let md = match &obj.metadata {
        Some(m) => m,
        None => return Ok(CreditOutcome::Ignored("no metadata")),
    };
    let user_id: Option<i64> = md.get("user_id").and_then(|s| s.parse().ok());
    let token = md.get("access_token").map(|s| s.as_str()).filter(|s| crate::security::valid_access_token(s));
    if user_id.is_none() && token.is_none() {
        return Ok(CreditOutcome::Ignored("no user in the metadata"));
    }
    if obj.payment_status.as_deref() != Some("paid") {
        return Ok(CreditOutcome::Ignored("payment_status is not paid"));
    }
    if let Some(cur) = obj.currency.as_deref() {
        if !cur.eq_ignore_ascii_case("usd") {
            error!(event = "stripe_wrong_currency", event_id, currency = cur);
            return Ok(CreditOutcome::Ignored("currency is not usd"));
        }
    }
    let cents = match obj.amount_total.and_then(|c| u64::try_from(c).ok()) {
        Some(c) => c,
        None => return Ok(CreditOutcome::Ignored("no amount_total")),
    };
    if gate::admitte_summam(cents).is_err() {
        error!(event = "stripe_amount_out_of_bounds", event_id, cents);
        return Ok(CreditOutcome::Ignored("amount_total outside 250..=10000 cents"));
    }
    // The checkout session id is the dedup key that makes "one payment, one credit" true when Stripe delivers
    // the payment as more than one event; the event id alone cannot, because each delivery has its own. Real
    // checkout.session.completed events always carry it, so an event without one is not credited at all.
    let session_id = match obj.id.as_deref().filter(|s| plausible_session_id(s)) {
        Some(id) => id,
        None => {
            error!(event = "stripe_event_without_session_id", event_id, "paid, ours, but no usable checkout session id; not credited");
            return Ok(CreditOutcome::Rejected("no usable checkout session id"));
        }
    };

    let mut tx = pool.begin().await?;
    let fresh = sqlx::query(
        "INSERT OR IGNORE INTO stripe_events (id, session_id, user_id, amount_cents, processed_at)
         VALUES (?, ?, NULL, ?, ?)",
    )
    .bind(event_id)
    .bind(session_id)
    .bind(cents as i64)
    .bind(Utc::now().to_rfc3339())
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    if !fresh {
        tx.rollback().await?;
        return Ok(CreditOutcome::Duplicate);
    }
    let found = match (user_id, token) {
        (Some(id), _) => sqlx::query("SELECT id FROM users WHERE id = ?").bind(id).fetch_optional(&mut *tx).await?,
        (None, Some(t)) => sqlx::query("SELECT id FROM users WHERE access_token = ?").bind(t).fetch_optional(&mut *tx).await?,
        (None, None) => None,
    };
    let uid: i64 = match found {
        Some(row) => row.try_get("id")?,
        None => {
            tx.commit().await?;
            error!(event = "stripe_payment_no_such_user", event_id, cents, "paid, recorded, not credited: needs a person");
            return Ok(CreditOutcome::NoSuchUser { cents });
        }
    };
    sqlx::query("UPDATE users SET account_balance = COALESCE(account_balance, 0.0) + ? WHERE id = ?")
        .bind(cents as f64 / 100.0)
        .bind(uid)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE stripe_events SET user_id = ? WHERE id = ?").bind(uid).bind(event_id).execute(&mut *tx).await?;
    tx.commit().await?;
    info!(event = "payment_processed", event_id, user_id = uid, amount_cents = cents);
    Ok(CreditOutcome::Credited { user_id: uid, cents })
}

pub fn warn_signature(e: &SignatureError) {
    match e {
        SignatureError::Stale => warn!(event = "stripe_webhook_stale"),
        SignatureError::Mismatch => warn!(event = "stripe_webhook_invalid_signature"),
        SignatureError::Shape(c) => warn!(event = "stripe_webhook_bad_header", verdict = *c),
        SignatureError::NoSecret => error!(event = "stripe_webhook_no_secret"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::testutil::*;

    const TOK: &str = "abcdefghijklmnopqrstuvwxyzABCDEF";
    const SECRET: &str = "whsec_test_secret";

    // ---- signature -------------------------------------------------------------
    fn sign(payload: &str, ts: i64, secret: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{ts}.{payload}").as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn signature_accepts_a_good_header_and_rejects_the_rest() {
        let body = r#"{"id":"evt_1"}"#;
        let now = 1_700_000_000;
        let good = sign(body, now, SECRET);
        let bad = "0".repeat(64);
        let ok = |h: &str| verify_stripe_signature(body, h, SECRET, now);
        assert_eq!(ok(&format!("t={now},v1={good}")), Ok(()));
        // secret rotation: any v1 may be the one that matches, wherever it is
        assert_eq!(ok(&format!("t={now},v1={good},v1={bad}")), Ok(()));
        assert_eq!(ok(&format!("t={now},v1={bad},v1={good}")), Ok(()));
        assert_eq!(ok(&format!("v1={bad},v1={bad},t={now},v1={good}")), Ok(()));
        // test mode sends v0 as well; it is ignored, never trusted
        assert_eq!(ok(&format!("t={now},v1={good},v0={bad}")), Ok(()));
        assert_eq!(ok(&format!("t={now},v0={good}")), Err(SignatureError::Shape(9)), "v0 alone is not a signature");
        assert_eq!(ok(&format!("t={now},v1={bad}")), Err(SignatureError::Mismatch));
        assert_eq!(ok(&format!("t={now},v1={bad},v1={bad}")), Err(SignatureError::Mismatch));
        // wrong body / wrong secret / wrong timestamp
        assert_eq!(verify_stripe_signature("{}", &format!("t={now},v1={good}"), SECRET, now), Err(SignatureError::Mismatch));
        assert_eq!(verify_stripe_signature(body, &format!("t={now},v1={good}"), "whsec_other", now), Err(SignatureError::Mismatch));
        assert_eq!(ok(&format!("t={},v1={good}", now + 1)), Err(SignatureError::Mismatch));
        // tolerance both ways
        let old = sign(body, now - 301, SECRET);
        assert_eq!(ok(&format!("t={},v1={old}", now - 301)), Err(SignatureError::Stale));
        let fut = sign(body, now + 301, SECRET);
        assert_eq!(ok(&format!("t={},v1={fut}", now + 301)), Err(SignatureError::Stale));
        let edge = sign(body, now - 300, SECRET);
        assert_eq!(ok(&format!("t={},v1={edge}", now - 300)), Ok(()));
        // shapes the gate refuses never reach the HMAC
        assert_eq!(ok(""), Err(SignatureError::Shape(1)));
        assert_eq!(ok(&format!("t={now}, v1={good}")), Err(SignatureError::Shape(3)));
        assert_eq!(ok(&format!("t={now},v1={}", good.to_uppercase())), Err(SignatureError::Shape(5)));
        assert_eq!(ok(&format!("v1={good}")), Err(SignatureError::Shape(8)));
        // an empty secret is a key anyone has: refused outright
        let forged = sign(body, now, "");
        assert_eq!(verify_stripe_signature(body, &format!("t={now},v1={forged}"), "", now), Err(SignatureError::NoSecret));
    }

    // ---- usage: the SQL against the old Rust formula ----------------------------------
    #[tokio::test]
    async fn usage_billing_matches_the_reference_formula() {
        let db = temp_db().await;
        seed(&db.pool, "meter", TOK, 0, 10.0, false).await;
        let mut used = 0i64;
        let mut bal = 10.0f64;
        for chunk in [1_000u64, 100_000_000, 40_000_000, 1 << 30, 3 << 30, 12345, 1 << 31] {
            apply_usage(&db.pool, TOK, chunk).await.unwrap();
            let next = used + chunk as i64;
            bal = (bal - reference_cost(used, next)).max(0.0);
            used = next;
            assert_eq!(used_of(&db).await, used);
            assert!((balance(&db.pool, TOK).await - bal).abs() < 1e-9, "after {chunk}: {} vs {bal}", balance(&db.pool, TOK).await);
        }
    }

    async fn used_of(db: &TempDb) -> i64 {
        used(&db.pool, TOK).await
    }

    #[tokio::test]
    async fn the_free_tier_is_free_and_the_balance_floors_at_zero() {
        let db = temp_db().await;
        seed(&db.pool, "freebie", TOK, 0, 1.0, false).await;
        apply_usage(&db.pool, TOK, FREE_TIER_BYTES as u64).await.unwrap();
        assert_eq!(balance(&db.pool, TOK).await, 1.0);
        apply_usage(&db.pool, TOK, 1 << 40).await.unwrap(); // ~ $51 against a $1 balance
        assert_eq!(balance(&db.pool, TOK).await, 0.0);
    }

    #[tokio::test]
    async fn vip_is_metered_but_never_billed() {
        let db = temp_db().await;
        seed(&db.pool, "vip", TOK, FREE_TIER_BYTES, 2.0, true).await;
        apply_usage(&db.pool, TOK, 1 << 34).await.unwrap();
        assert_eq!(balance(&db.pool, TOK).await, 2.0);
        assert_eq!(used(&db.pool, TOK).await, FREE_TIER_BYTES + (1 << 34));
    }

    #[tokio::test]
    async fn huge_reports_are_refused_and_change_nothing() {
        let db = temp_db().await;
        seed(&db.pool, "meter", TOK, 1000, 5.0, false).await;
        for bytes in [MAX_REPORT_BYTES + 1, 1 << 62, (1u64 << 63) - 1, 1 << 63, u64::MAX, u64::MAX - 499] {
            assert!(matches!(apply_usage(&db.pool, TOK, bytes).await, Err(UsageError::TooLarge)), "{bytes}");
        }
        assert_eq!(used(&db.pool, TOK).await, 1000);
        assert_eq!(balance(&db.pool, TOK).await, 5.0);
        apply_usage(&db.pool, TOK, MAX_REPORT_BYTES).await.unwrap(); // the cap itself is allowed
        assert_eq!(used(&db.pool, TOK).await, 1000 + MAX_REPORT_BYTES as i64);
    }

    #[tokio::test]
    async fn repeated_max_reports_stop_at_the_ceiling_without_wrapping() {
        let db = temp_db().await;
        seed(&db.pool, "meter", TOK, MAX_DATA_USED - 5, 5.0, true).await;
        assert!(matches!(apply_usage(&db.pool, TOK, 10).await, Err(UsageError::OutOfRange)));
        assert_eq!(used(&db.pool, TOK).await, MAX_DATA_USED - 5, "refused, not wrapped");
        assert!(apply_usage(&db.pool, TOK, 5).await.is_ok());
        // a counter damaged by the old overflow bug is refused and left alone, not made worse
        sqlx::query("UPDATE users SET data_used = ?").bind(i64::MIN + 7).execute(&db.pool).await.unwrap();
        assert!(matches!(apply_usage(&db.pool, TOK, 1).await, Err(UsageError::OutOfRange)));
        assert_eq!(used(&db.pool, TOK).await, i64::MIN + 7);
    }

    #[tokio::test]
    async fn unknown_token_is_not_found() {
        let db = temp_db().await;
        assert!(matches!(apply_usage(&db.pool, TOK, 1).await, Err(UsageError::NotFound)));
    }

    #[tokio::test]
    async fn null_columns_are_treated_as_zero_by_the_update() {
        let db = temp_db().await;
        seed(&db.pool, "nulls", TOK, 1, 1.0, false).await;
        sqlx::query("UPDATE users SET data_used = NULL, account_balance = NULL, is_vip = NULL").execute(&db.pool).await.unwrap();
        apply_usage(&db.pool, TOK, 7).await.unwrap();
        assert_eq!(used(&db.pool, TOK).await, 7);
    }

    // ---- I5: usage and credit race ----------------------------------------------------
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_credits_and_usage_reports_lose_no_money() {
        let db = temp_db().await;
        for round in 0..3 {
            let tok = format!("{:A<32}", format!("race{round}"));
            seed(&db.pool, &format!("racer{round}"), &tok, FREE_TIER_BYTES, 1000.0, false).await;
            let n = 40usize;
            let mut handles = vec![];
            for i in 0..n {
                let (pool_a, tok_a) = (db.pool.clone(), tok.clone());
                handles.push(tokio::spawn(async move {
                    let ev = event(&format!("evt_race{round}_{i}"), &format!("cs_race{round}_{i}"), &tok_a, 500, "paid");
                    matches!(credit_checkout(&pool_a, &ev).await, Ok(CreditOutcome::Credited { .. }))
                }));
                let (pool_b, tok_b) = (db.pool.clone(), tok.clone());
                handles.push(tokio::spawn(async move { apply_usage(&pool_b, &tok_b, 1 << 30).await.is_ok() }));
            }
            for h in handles {
                assert!(h.await.unwrap(), "a request failed");
            }
            let expected = 1000.0 + n as f64 * 5.0 - n as f64 * 0.05;
            let got = balance(&db.pool, &tok).await;
            assert!((got - expected).abs() < 1e-6, "round {round}: balance {got}, expected {expected}");
            assert_eq!(used(&db.pool, &tok).await, FREE_TIER_BYTES + n as i64 * (1 << 30));
        }
    }

    // ---- I6: stripe credits -----------------------------------------------------------
    fn event(id: &str, session: &str, token: &str, cents: i64, status: &str) -> StripeEvent {
        let mut md = HashMap::new();
        md.insert("access_token".to_string(), token.to_string());
        md.insert("amount_dollars".to_string(), "99.00".to_string()); // never read
        StripeEvent {
            id: Some(id.to_string()),
            event_type: "checkout.session.completed".into(),
            data: StripeEventData {
                object: StripeCheckoutSession {
                    id: Some(session.to_string()),
                    amount_total: Some(cents),
                    currency: Some("usd".into()),
                    payment_status: Some(status.to_string()),
                    metadata: Some(md),
                },
            },
        }
    }

    #[tokio::test]
    async fn a_replayed_event_credits_once() {
        let db = temp_db().await;
        seed(&db.pool, "payer", TOK, 0, 0.0, false).await;
        let ev = event("evt_1", "cs_1", TOK, 500, "paid");
        assert!(matches!(credit_checkout(&db.pool, &ev).await.unwrap(), CreditOutcome::Credited { cents: 500, .. }));
        assert_eq!(credit_checkout(&db.pool, &ev).await.unwrap(), CreditOutcome::Duplicate);
        assert_eq!(credit_checkout(&db.pool, &ev).await.unwrap(), CreditOutcome::Duplicate);
        assert_eq!(balance(&db.pool, TOK).await, 5.0);
        // a different event id for the same checkout session is the same payment
        let ev2 = event("evt_2", "cs_1", TOK, 500, "paid");
        assert_eq!(credit_checkout(&db.pool, &ev2).await.unwrap(), CreditOutcome::Duplicate);
        assert_eq!(balance(&db.pool, TOK).await, 5.0);
        // a genuinely new payment credits
        let ev3 = event("evt_3", "cs_3", TOK, 1000, "paid");
        assert!(matches!(credit_checkout(&db.pool, &ev3).await.unwrap(), CreditOutcome::Credited { cents: 1000, .. }));
        assert_eq!(balance(&db.pool, TOK).await, 15.0);
    }

    #[tokio::test]
    async fn concurrent_deliveries_of_one_event_credit_once() {
        let db = temp_db().await;
        seed(&db.pool, "payer", TOK, 0, 0.0, false).await;
        let mut handles = vec![];
        for _ in 0..16 {
            let pool = db.pool.clone();
            handles.push(tokio::spawn(async move {
                credit_checkout(&pool, &event("evt_same", "cs_same", TOK, 500, "paid")).await.unwrap()
            }));
        }
        let mut credited = 0;
        for h in handles {
            if matches!(h.await.unwrap(), CreditOutcome::Credited { .. }) {
                credited += 1;
            }
        }
        assert_eq!(credited, 1);
        assert_eq!(balance(&db.pool, TOK).await, 5.0);
    }

    #[tokio::test]
    async fn the_credit_is_stripes_amount_total_not_metadata() {
        let db = temp_db().await;
        seed(&db.pool, "payer", TOK, 0, 0.0, false).await;
        // metadata claims $99.00 (see event()); Stripe says 250 cents
        credit_checkout(&db.pool, &event("evt_a", "cs_a", TOK, 250, "paid")).await.unwrap();
        assert_eq!(balance(&db.pool, TOK).await, 2.5);
    }

    #[tokio::test]
    async fn unpaid_wrong_currency_and_out_of_bounds_are_not_credited() {
        let db = temp_db().await;
        seed(&db.pool, "payer", TOK, 0, 0.0, false).await;
        for (i, status) in ["unpaid", "no_payment_required", ""].iter().enumerate() {
            let out = credit_checkout(&db.pool, &event(&format!("evt_u{i}"), &format!("cs_u{i}"), TOK, 500, status)).await.unwrap();
            assert!(matches!(out, CreditOutcome::Ignored(_)), "{status}");
        }
        for (i, cents) in [0i64, 249, 10001, 99_999_999, -500, i64::MAX, i64::MIN].iter().enumerate() {
            let out = credit_checkout(&db.pool, &event(&format!("evt_b{i}"), &format!("cs_b{i}"), TOK, *cents, "paid")).await.unwrap();
            assert!(matches!(out, CreditOutcome::Ignored(_)), "{cents}");
        }
        let mut ev = event("evt_c", "cs_c", TOK, 500, "paid");
        ev.data.object.currency = Some("eur".into());
        assert!(matches!(credit_checkout(&db.pool, &ev).await.unwrap(), CreditOutcome::Ignored(_)));
        let mut ev = event("evt_d", "cs_d", TOK, 500, "paid");
        ev.data.object.amount_total = None;
        assert!(matches!(credit_checkout(&db.pool, &ev).await.unwrap(), CreditOutcome::Ignored(_)));
        assert_eq!(balance(&db.pool, TOK).await, 0.0);
        // an ignored event leaves no record: the same id, now paid, credits
        let out = credit_checkout(&db.pool, &event("evt_u0", "cs_u0", TOK, 500, "paid")).await.unwrap();
        assert!(matches!(out, CreditOutcome::Credited { .. }));
    }

    #[tokio::test]
    async fn the_user_comes_from_user_id_or_the_legacy_token_and_nothing_else() {
        let db = temp_db().await;
        seed(&db.pool, "payer", TOK, 0, 0.0, false).await;
        let id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE access_token = ?").bind(TOK).fetch_one(&db.pool).await.unwrap();
        let mut ev = event("evt_i", "cs_i", "unused", 500, "paid");
        let md = ev.data.object.metadata.as_mut().unwrap();
        md.remove("access_token");
        md.insert("user_id".into(), id.to_string());
        assert_eq!(credit_checkout(&db.pool, &ev).await.unwrap(), CreditOutcome::Credited { user_id: id, cents: 500 });
        // user_id wins over a token naming someone else
        seed(&db.pool, "other", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", 0, 0.0, false).await;
        let mut ev = event("evt_j", "cs_j", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", 500, "paid");
        ev.data.object.metadata.as_mut().unwrap().insert("user_id".into(), id.to_string());
        credit_checkout(&db.pool, &ev).await.unwrap();
        assert_eq!(balance(&db.pool, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").await, 0.0);
        assert_eq!(balance(&db.pool, TOK).await, 10.0);
        // no user information at all
        let mut ev = event("evt_k", "cs_k", TOK, 500, "paid");
        ev.data.object.metadata.as_mut().unwrap().remove("access_token");
        assert!(matches!(credit_checkout(&db.pool, &ev).await.unwrap(), CreditOutcome::Ignored(_)));
        ev.data.object.metadata = None;
        assert!(matches!(credit_checkout(&db.pool, &ev).await.unwrap(), CreditOutcome::Ignored(_)));
        // a user_id that names nobody: recorded (so Stripe stops retrying), nothing credited
        let mut ev = event("evt_l", "cs_l", TOK, 500, "paid");
        let md = ev.data.object.metadata.as_mut().unwrap();
        md.remove("access_token");
        md.insert("user_id".into(), "999999".into());
        assert_eq!(credit_checkout(&db.pool, &ev).await.unwrap(), CreditOutcome::NoSuchUser { cents: 500 });
        assert_eq!(credit_checkout(&db.pool, &ev).await.unwrap(), CreditOutcome::Duplicate);
    }

    #[tokio::test]
    async fn an_event_without_a_usable_id_is_not_credited() {
        let db = temp_db().await;
        seed(&db.pool, "payer", TOK, 0, 0.0, false).await;
        for id in [None, Some(""), Some("evt 1; drop"), Some(&*"e".repeat(300))] {
            let mut ev = event("x", "cs_x", TOK, 500, "paid");
            ev.id = id.map(|s| s.to_string());
            assert!(matches!(credit_checkout(&db.pool, &ev).await.unwrap(), CreditOutcome::Ignored(_)), "{id:?}");
        }
        assert_eq!(balance(&db.pool, TOK).await, 0.0);
    }

    #[tokio::test]
    async fn an_event_without_a_plausible_checkout_session_id_is_never_credited() {
        // Without a session id the only dedup key is the event id, and two different event ids for one
        // payment would both credit. Real checkout.session.completed events always carry the session id.
        let db = temp_db().await;
        seed(&db.pool, "payer", TOK, 0, 0.0, false).await;
        let too_long = format!("cs_{}", "y".repeat(300));
        let cases: Vec<Option<&str>> = vec![None, Some(""), Some("evt_looks_like_an_event"), Some("cs_has space"), Some("cs_semi;colon"), Some(&too_long), Some("cs_")];
        for (i, session) in cases.iter().enumerate() {
            for twin in 0..2 {
                let mut ev = event(&format!("evt_nosess_{i}_{twin}"), "ignored", TOK, 500, "paid");
                ev.data.object.id = session.map(|s| s.to_string());
                let out = credit_checkout(&db.pool, &ev).await.unwrap();
                assert!(matches!(out, CreditOutcome::Rejected(_)), "session id {session:?}: {out:?}");
            }
        }
        assert_eq!(balance(&db.pool, TOK).await, 0.0);
        // with a real-shaped id: once, however many event ids carry it
        for k in 0..3 {
            let ev = event(&format!("evt_real_{k}"), "cs_test_a1B2c3", TOK, 500, "paid");
            let out = credit_checkout(&db.pool, &ev).await.unwrap();
            assert_eq!(matches!(out, CreditOutcome::Credited { .. }), k == 0, "delivery {k}: {out:?}");
        }
        assert_eq!(balance(&db.pool, TOK).await, 5.0);
    }

    #[test]
    fn real_stripe_payload_shape_deserialises() {
        let body = r#"{"id":"evt_1NG8Du2eZvKYlo2CUI79vXWy","object":"event","api_version":"2022-11-15","created":1686089970,
          "type":"checkout.session.completed","livemode":false,"pending_webhooks":1,
          "data":{"object":{"id":"cs_test_a1","object":"checkout.session","amount_subtotal":500,"amount_total":500,
          "currency":"usd","payment_status":"paid","status":"complete","mode":"payment","metadata":{"user_id":"7"}}}}"#;
        let ev: StripeEvent = serde_json::from_str(body).unwrap();
        assert_eq!(ev.id.as_deref(), Some("evt_1NG8Du2eZvKYlo2CUI79vXWy"));
        assert_eq!(ev.data.object.amount_total, Some(500));
        assert_eq!(ev.data.object.metadata.unwrap()["user_id"], "7");
    }
}
