# DCF-ID: Identity & Billing Service

A lightweight, high-performance identity and billing service for game networking infrastructure. Built with Rust for maximum reliability and minimal resource usage.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/F1F11PNYX4)

## Features

- **User Authentication**: Username/password and Discord OAuth2
- **Session Management**: Secure, token-based sessions with automatic expiration
- **Usage Tracking**: Per-user bandwidth metering with free tier (128MB)
- **Billing Integration**: Stripe checkout for credit purchases
- **Rate Limiting**: IP-based login attempt throttling
- **VIP System**: Override billing for privileged users
- **Health Monitoring**: `/health` and `/metrics` endpoints

## Quick Start

### Docker

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
# Requires Rust 1.85+
cargo build --release
./target/release/dcf-id
```

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
| `RUST_LOG` | No | `dcf_id=info` | Log level |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard/login page |
| `GET` | `/health` | Health check (JSON) |
| `GET` | `/metrics` | Service metrics (JSON) |
| `POST` | `/auth/register` | Create account |
| `POST` | `/auth/login` | Login with credentials |
| `POST` | `/auth/logout` | End session |
| `GET` | `/auth/discord` | Start Discord OAuth flow |
| `GET` | `/auth/callback` | Discord OAuth callback |
| `POST` | `/checkout` | Create Stripe checkout session |
| `POST` | `/stripe/webhook` | Stripe webhook handler |

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

- **Free Tier**: 128 MB bandwidth per month
- **Paid**: $0.05 per GB beyond free tier
- **Credits**: $5.00 = 100 GB prepaid
- **VIP**: Unlimited (set `is_vip=1` in database)

Usage resets monthly. Overage is deducted from account balance.

## Security

- Passwords hashed with Argon2id
- Constant-time password comparison
- HMAC-SHA256 webhook signature verification
- HttpOnly session cookies
- IP-based rate limiting (5 attempts, 15 min lockout)

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
