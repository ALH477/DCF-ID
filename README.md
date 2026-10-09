# DCF-ID: Identity & Billing Service

A lightweight, high-performance identity and billing service for game networking infrastructure. Built with Rust for maximum reliability and minimal resource usage.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/F1F11PNYX4)

## Features

- **User Authentication**: Username/password and Discord OAuth2
- **Session Management**: Secure, token-based sessions with automatic expiration
- **Usage Tracking**: Per-user bandwidth metering with free tier (128MB)
- **Billing Integration**: Stripe checkout for credit purchases
- **Rate Limiting**: login attempts throttled per client address and per username, registrations per address (Redis, with a bounded in-process fallback)
- **VIP System**: Override billing for privileged users
- **Health Monitoring**: `/health` (open, minimal) and `/metrics` (needs the internal key)

## Quick Start

### Docker

> **[UNVERIFIED]** This repository contains no Dockerfile, so nothing here builds the image named below,
> and whether `alh477/dcf-id` exists was not checked. The two Docker snippets are kept as the owner wrote
> them; the new variables below (`DCF_ID_INTERNAL_KEY` is now required) are not in them.

```bash
docker pull alh477/dcf-id:latest

docker run -d \
  -p 4000:4000 \
  -e DATABASE_URL=sqlite:/data/identity.db \
  -e STRIPE_SECRET_KEY=sk_live_... \
  -e STRIPE_WEBHOOK_SECRET=whsec_... \
  -e DISCORD_CLIENT_ID=... \
  -e DISCORD_CLIENT_SECRET=... \
  -e BASE_URL=https://your-domain.com \
  -v dcf-data:/data \
  alh477/dcf-id:latest
```

### Docker Compose

```yaml
services:
  dcf-id:
    image: alh477/dcf-id:latest
    ports:
      - "4000:4000"
    environment:
      - DATABASE_URL=sqlite:/data/identity.db
      - STRIPE_SECRET_KEY=sk_live_...
      - STRIPE_WEBHOOK_SECRET=whsec_...
      - DISCORD_CLIENT_ID=...
      - DISCORD_CLIENT_SECRET=...
      - DISCORD_REDIRECT_URL=https://your-domain.com/auth/callback
      - BASE_URL=https://your-domain.com
    volumes:
      - dcf-data:/data

volumes:
  dcf-data:
```

### Build from Source

```bash
cargo build --release          # needs a C11 compiler (cc) for the vendored Exsecutor gate in gate/
./target/release/dcf-id
```

- Built and tested here with Rust 1.97. The earlier "Rust 1.85+" claim was not checked. [UNVERIFIED]
- **`templates/index.html` is not in this repository** (`askama.toml` points at `templates/`), so the binary
  cannot be built from a clean clone. The library half builds and tests without it: `cargo test --lib`.
- At the commit before this change the binary did not compile even with a template: `health_check` called
  `redis::cmd(..).query_async::<String>(..)`, the redis 0.26 signature, against the locked redis 0.25.4.
  It now awaits `query_async::<_, String>`.

## Configuration

| Environment Variable | Required | Default | Description |
|---------------------|----------|---------|-------------|
| `DATABASE_URL` | No | `sqlite:/data/identity.db` | SQLite database path |
| `IDENTITY_PORT` | No | `4000` | HTTP listen port |
| `BASE_URL` | No | `http://localhost:4000` | Public URL for redirects |
| `STRIPE_SECRET_KEY` | Yes | - | Stripe API secret key |
| `STRIPE_WEBHOOK_SECRET` | Yes | - | Stripe webhook signing secret |
| `DISCORD_CLIENT_ID` | Yes | - | Discord OAuth2 client ID |
| `DISCORD_CLIENT_SECRET` | Yes | - | Discord OAuth2 client secret |
| `DISCORD_REDIRECT_URL` | No | `{BASE_URL}/auth/callback` | OAuth2 callback URL |
| `DCF_ID_INTERNAL_KEY` | **Yes**, unless `DCF_ID_ALLOW_OPEN_API=1` | - | Shared secret for the internal API: callers send `X-Internal-Key: <key>`. Without it the service refuses to start. |
| `DCF_ID_ALLOW_OPEN_API` | No | unset | `1` runs the internal API (which returns access tokens and moves balances) with **no authentication**, and logs an error saying so at startup. Do not set it on a reachable port. |
| `TRUSTED_PROXIES` | No | empty | Comma-separated IPs / CIDRs (`10.0.0.0/8, 192.168.1.1, fd00::/8`) of reverse proxies whose `X-Forwarded-For` is believed. Empty trusts nobody: the socket peer is the client address. **Behind a reverse proxy you must set this**, or every client appears to be the proxy (and 5 bad logins lock everyone out). A typo is a startup error. |
| `REDIS_URL` | No | `redis://127.0.0.1:6379` | Sessions, OAuth state and throttle counters. If unreachable, sessions do not persist and throttles fall back to a per-process limiter. |
| `RUST_LOG` | No | `dcf_id=info` | Log level |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard/login page |
| `GET` | `/health` | Health check: `{"status":"healthy"|"degraded"}` only, open |
| `GET` | `/metrics` | Service metrics (JSON), needs `X-Internal-Key` |
| `POST` | `/auth/register` | Create account |
| `POST` | `/auth/login` | Login with credentials |
| `POST` | `/auth/logout` | End session |
| `GET` | `/auth/discord` | Start Discord OAuth flow |
| `GET` | `/auth/callback` | Discord OAuth callback |
| `POST` | `/checkout` | Create Stripe checkout session |
| `POST` | `/stripe/webhook` | Stripe webhook handler |
| `GET` | `/api/user/discord/:discord_id` | Look a user up by Discord id (returns the access token), needs `X-Internal-Key` |
| `GET` | `/api/user/verify` | Check an access token: `Authorization: Bearer <32-char token>` |
| `POST` | `/api/usage/report` | `{"access_token", "bytes_used"}` (at most 2^40 per report), needs `X-Internal-Key` |
| `GET` | `/api/stats` | Totals, needs `X-Internal-Key` |

## Database Schema

SQLite database with automatic migration on startup:

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password_hash TEXT,
    access_token TEXT UNIQUE,
    discord_id TEXT UNIQUE,
    data_used INTEGER DEFAULT 0,
    account_balance REAL DEFAULT 0.00,
    last_reset_date TEXT,
    last_ip TEXT,
    last_seen TEXT,
    created_at TEXT,
    is_vip INTEGER DEFAULT 0
);

-- added by this change; created on startup
CREATE UNIQUE INDEX idx_users_username_nocase ON users(username COLLATE NOCASE);  -- skipped (logged) if old rows collide
CREATE TABLE stripe_events (
    id TEXT PRIMARY KEY,          -- Stripe event id: a delivery is credited once
    session_id TEXT UNIQUE,       -- Checkout session id: a payment is credited once
    user_id INTEGER,
    amount_cents INTEGER NOT NULL,
    processed_at TEXT NOT NULL
);
```

## Integration

### Access Token Usage

After registration/login, users receive an `access_token`. Use this token in your game client to authenticate with DCF-SDK:

```toml
# dcf_config.toml
access_token = "your_32_char_token_here"
```

### Webhook Setup (Stripe)

1. Create webhook endpoint in Stripe Dashboard
2. URL: `https://your-domain.com/stripe/webhook`
3. Events: `checkout.session.completed`
4. Copy signing secret to `STRIPE_WEBHOOK_SECRET`

### OAuth Setup (Discord)

1. Create application at https://discord.com/developers/applications
2. Add redirect URL: `https://your-domain.com/auth/callback`
3. Copy Client ID and Client Secret

## Billing Model

- **Free Tier**: 128 MB bandwidth ("per month": see the note below)
- **Paid**: $0.05 per GB beyond free tier
- **Credits**: $5.00 = 100 GB prepaid
- **VIP**: Unlimited (set `is_vip=1` in database)

Overage is deducted from account balance.

> **[UNVERIFIED]** "Usage resets monthly" was claimed here. Nothing in this repository resets `data_used`
> (`last_reset_date` is written at registration and never read), so if a reset happens it happens elsewhere.

## Security

How it stands now:

- Passwords are hashed with Argon2 (`Argon2::default()`) and checked with the `argon2` crate's `verify_password`.
- Stripe webhooks: HMAC-SHA256 over `t.payload` (`hmac`/`sha2`, compared in constant time against **every** `v1`),
  5-minute tolerance, and each event credited at most once.
- The internal API needs `X-Internal-Key` (compared in constant time) and the service will not start without one.
- Session cookies are `HttpOnly; SameSite=Lax` (`Secure` when `BASE_URL` is https).
- Everything a stranger controls and that reaches Redis, SQL or the firewall daemon's input passes an
  [Exsecutor](https://github.com/ALH477/exsecutor) gate first (`gate/`, wrapper in `src/gate.rs`): usernames,
  session ids, access tokens and OAuth state, checkout amounts, the `Stripe-Signature` header's shape, and
  the client address stored in `users.last_ip` (the root watchdog turns that column into `nft` rules).
  Provenance and the licence status of the vendored C are in `gate/PROVENANCE.md`.

### Security changes

Every behaviour change in this revision. Callers, operators and the game servers will notice some of these.

**Operators**
- **`DCF_ID_INTERNAL_KEY` is required.** Unset or empty, the service exits at startup. `DCF_ID_ALLOW_OPEN_API=1`
  restores the old open behaviour and logs an error. Before, an empty key meant every internal endpoint was open.
- **`X-Forwarded-For` is ignored unless the peer is in `TRUSTED_PROXIES`** (default empty). Rate limits and
  `users.last_ip` now use the socket peer. If DCF-ID sits behind a reverse proxy and you do not set
  `TRUSTED_PROXIES`, all users share the proxy's address. When the peer is trusted, the **rightmost** entry that
  is not itself a trusted proxy is the client; an entry that is not a plain IP address ends the walk at the peer.
- An empty `STRIPE_WEBHOOK_SECRET` is refused at startup (an empty HMAC key is a key everyone has).
- Request bodies over 64 KiB are refused with 413 (the framework default was 2 MB).
- Redis connections time out after 1.5 s, so an unreachable Redis degrades quickly instead of hanging requests.
- Rows whose `data_used` is outside +-2^62 (only possible from the old overflow, see below) are not touched by usage
  reports (HTTP 409). Repair them by hand after looking at them.

**Callers of the internal API** (`X-Internal-Key`)
- `/api/stats` and `/metrics` now need the key. They were open.
- `/health` returns only `{"status": ...}`; `uptime_secs`, `redis_ok` and `version` are gone.
- `POST /api/usage/report`: `bytes_used` above 2^40 (1 TiB) is **400** (before, `u64::MAX` wrapped to -1 and
  subtracted usage; `2^63-1` locked an account); a malformed `access_token` is 404, like an unknown one; error
  bodies no longer carry SQL error text. Billing is one atomic `UPDATE`, so a concurrent Stripe credit cannot be
  overwritten by a usage report.
- `GET /api/user/verify` answers 401 without querying for a token that is not exactly 32 ASCII alphanumerics.
- `GET /api/user/discord/:id` answers 404 for an id that is not 1..=20 digits.

**Billing**
- A `checkout.session.completed` event is credited **once** (table `stripe_events`, keyed by event id and by checkout
  session id), only when `payment_status` is `paid` and the currency is USD, for Stripe's own integer `amount_total`
  (not `metadata.amount_dollars`), and only for 250..=10000 cents. A database failure answers 500 so Stripe retries.
- Checkout sessions now carry `metadata[user_id]` (the row id) instead of the secret access token. Events from sessions
  created before this change (access token in the metadata) are still credited.
- `amount=NaN` is refused (it passed the old range test); the amount goes through the `admitte_summam` gate.
- `Stripe-Signature` is shape-checked by a gate before parsing; every `v1` is tried (secret rotation); `v0` is ignored.

**Accounts and login**
- New usernames: ASCII `[A-Za-z0-9_-]`, 3..=32 bytes (before, any Unicode alphanumeric: a Cyrillic look-alike of `admin`
  was a second account). Existing non-ASCII usernames can still log in; they cannot be registered again.
- Usernames are unique ignoring ASCII case (`Alice` and `alice` are one name). Existing duplicates are left as they are;
  the unique index is skipped (logged) if any exist, and registration checks inside the `INSERT` instead.
- Passwords: 8..=256 bytes. Login refuses a longer one without hashing it.
- Registration is limited to 10 attempts per address per hour (attempts that pass validation and reach the hash).
- Login lockout: 5 failures per address per 15 minutes (as before) **and** 20 failures per username (any address,
  case-folded) per 15 minutes. If Redis is unreachable a bounded in-process limiter (10,000 keys, per process,
  forgotten on restart) takes over; before, an unreachable Redis meant no limit at all.
- Cookie values (`session`, `oauth_state`) and OAuth `state` are shape-checked (64 / 32 ASCII alphanumerics) before
  they are used as Redis keys.

**Discord sign-in**
- The flow is bound to the browser that started it: `/auth/discord` sets an `HttpOnly; SameSite=Lax; Path=/auth`
  `oauth_state` cookie and the callback requires it to match `state` (constant-time) before the single-use Redis check.
  Before, any valid `state` worked in any browser (login CSRF: the victim is signed in as the attacker and pays into the
  attacker's account).
- `GET /auth/discord?link_discord=<id>` no longer does anything. It stored an unauthenticated Redis key whose value the
  callback read and threw away.
- Discord display names are cut down to `[A-Za-z0-9_-]` (other characters dropped), `discord_<id>` if fewer than 3
  remain, and suffixed `_1`, `_2`... within 32 bytes if taken (ignoring case).

**Responses**
- Every response carries `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`
  and `Cache-Control: no-store`; `Strict-Transport-Security` when `BASE_URL` is https.
  **No `Content-Security-Policy` is sent**: the template is not in this repository, so whether it needs inline script
  or style is unknown. [OPEN]
- `last_ip` holds the canonical spelling of the address; an IPv4 address the shared `admitte_ipv4` gate does not admit
  is not stored (logged). IPv6 is stored in its canonical form; the watchdog's own gate decides what to do with it.

**Code**
- The repository is a library (`src/lib.rs`: everything that is not HTML) and a binary (`src/main.rs`: template, HTML
  handlers, wiring). Rows are read with `try_get`; a NULL numeric column reads as 0 and a mistyped one is an error, never a
  panic (release builds use `panic = "abort"`, so a panic ends the process). This is hardening for a row with TEXT or a BLOB
  in a numeric or text column: an earlier review expected a Discord-created user (`password_hash` NULL) logging in to abort the
  process, but sqlx-sqlite 0.7.4 decodes NULL as `""` / `0` / `0.0` through `Row::get`, and that was measured not to happen.

### Known gaps

- `[OPEN]` **Password login and registration are not CSRF-protected.** `SameSite=Lax` does not stop a cross-site `POST` from
  setting the session cookie, so a login-CSRF through `/auth/login` remains possible. The OAuth path is fixed; this one needs
  a token in the form (the template) or an `Origin` check. Not changed here.
- `[OPEN]` The `oauth_state` and `session` cookies are not `__Host-` prefixed: a sibling subdomain you do not control can set
  them (cookie tossing). `__Host-` needs `Secure` and `Path=/`.
- `[OPEN]` Argon2 runs on the async worker thread, and the lockout is checked before but recorded after the hash, so a burst of
  parallel logins from one address is not stopped at five. Pre-existing.
- `[OPEN]` No `Content-Security-Policy` (see above).
- `[UNTESTED]` Anything that needs Discord or Stripe themselves: the token exchange, `/users/@me`, creating a real Checkout
  session. The webhook is exercised with events signed locally; the callback is exercised only as far as the state check and,
  with Discord unreachable, the failed token exchange.
- The licence is stated twice and differently: `Cargo.toml` says `Proprietary`, this README says BSD 3-Clause. The vendored
  gate's own licence status is separate and **pending owner decision** (`gate/PROVENANCE.md`).
- No `Dockerfile`, CI or `templates/` in the repository.

### Tests

```bash
cargo test --lib                                   # 76 tests: gate, throttles, billing, API on a real socket; needs no template
                                                   # (the Redis-backed ones run if a redis-server binary is on PATH)
scripts/check-gate-fresh.sh                        # vendored gate == what its provenance says (re-emits if EXSECUTOR=... is set)
python3 tests/poc/poc.py target/release/dcf-id     # black-box exploit programs against a built binary (needs the template)
```

`tests/poc/poc.py` is the regression suite for the findings: 39 checks, each either an exploit (`I*`, `[VULN]` if it works)
or a guard that the legitimate path still works (`R*`). Against the commit before this change (with only a compile fix and a
scratch template) it reports 26 VULN, 13 ok; against this one, 39 ok. The template it expects is described in its header.

## License

BSD 3-Clause License

Copyright (c) 2024-2025, DeMoD LLC

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
