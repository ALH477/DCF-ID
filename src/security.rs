// ============================================================================
// Security helpers: who the client is, who may call the internal API, what a
// cookie may contain, and the headers every response carries.
// ============================================================================
use crate::gate::{self, Genus};
use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use subtle::ConstantTimeEq;
use tracing::warn;

// ---------------------------------------------------------------------------
// Constants shared by the handlers
// ---------------------------------------------------------------------------
pub const MIN_PASSWORD_LENGTH: usize = 8;
/// Argon2 is memory-hard, so its cost does not grow with the password; this
/// bounds the work done *before* hashing (the form body is capped as well).
pub const MAX_PASSWORD_LENGTH: usize = 256;
/// A login may name a legacy (pre-gate) username that is not ASCII; it is only
/// ever a bound SQL parameter. This bounds it.
pub const MAX_LOGIN_USERNAME_BYTES: usize = 128;
pub const MAX_USERNAME_LENGTH: usize = 32;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------
/// A username a NEW account may have: the Exsecutor gate (ASCII `[A-Za-z0-9_-]`, 3..=32).
pub fn validate_username(username: &str) -> Result<(), String> {
    match gate::admitte_nomen(username) {
        Ok(()) => Ok(()),
        Err(_) => Err(format!(
            "Username must be 3-{} characters: ASCII letters, numbers, _ and -",
            MAX_USERNAME_LENGTH
        )),
    }
}

pub fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(format!("Password must be at least {} characters", MIN_PASSWORD_LENGTH));
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(format!("Password must be at most {} bytes", MAX_PASSWORD_LENGTH));
    }
    Ok(())
}

/// A Discord snowflake: 1..=20 ASCII digits.
pub fn valid_discord_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 20 && id.bytes().all(|b| b.is_ascii_digit())
}

pub fn valid_session_id(s: &str) -> bool {
    gate::admitte_signum(s, Genus::Session).is_ok()
}

pub fn valid_access_token(s: &str) -> bool {
    gate::admitte_signum(s, Genus::Token).is_ok()
}

/// Make a Discord display name into a username the gate admits, or fall back to
/// `discord_<id>`. Characters outside `[A-Za-z0-9_-]` are dropped (not mapped:
/// dropping cannot turn two different names into a look-alike of a third).
pub fn sanitize_discord_username(raw: &str, discord_id: &str) -> String {
    let kept: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(MAX_USERNAME_LENGTH)
        .collect();
    if gate::admitte_nomen(&kept).is_ok() {
        return kept;
    }
    let digits: String = discord_id.chars().filter(|c| c.is_ascii_digit()).take(20).collect();
    let fallback = format!("discord_{}", digits);
    if gate::admitte_nomen(&fallback).is_ok() {
        fallback
    } else {
        // discord_ + nothing is 8 bytes and admitted, so this is only reached for an
        // id that is empty after filtering; the gate still admits "discord_".
        "discord_user".to_string()
    }
}

/// `base` followed by `_<attempt>`, with `base` cut so the whole fits 32 bytes.
pub fn username_with_suffix(base: &str, attempt: u32) -> String {
    if attempt == 0 {
        return base.to_string();
    }
    let suffix = format!("_{}", attempt);
    let keep = MAX_USERNAME_LENGTH.saturating_sub(suffix.len()).min(base.len());
    format!("{}{}", &base[..keep], suffix)
}

// ---------------------------------------------------------------------------
// Constant-time comparison
// ---------------------------------------------------------------------------
/// Equal bytes, in time that depends on neither the contents nor the lengths
/// (both sides are hashed first, so the compared values always have 32 bytes).
pub fn ct_eq_str(a: &[u8], b: &[u8]) -> bool {
    let ha = Sha256::digest(a);
    let hb = Sha256::digest(b);
    ha.as_slice().ct_eq(hb.as_slice()).into()
}

// ---------------------------------------------------------------------------
// The internal (bot / game-server) API key
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiAuth {
    /// Requests must carry `X-Internal-Key: <key>`; only its SHA-256 is kept here.
    Keyed([u8; 32]),
    /// Explicitly opened by DCF_ID_ALLOW_OPEN_API=1. Never the default.
    Open,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConfigError {
    MissingInternalKey,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingInternalKey => write!(
                f,
                "DCF_ID_INTERNAL_KEY is not set. The internal API hands out access tokens and moves \
                 balances; refusing to start without a key. Set DCF_ID_INTERNAL_KEY, or set \
                 DCF_ID_ALLOW_OPEN_API=1 to run it open (do not do that on a reachable port)."
            ),
        }
    }
}

impl ApiAuth {
    /// Fail closed: no key (unset or empty) is an error unless `allow_open`.
    pub fn from_config(key: Option<&str>, allow_open: bool) -> Result<Self, ConfigError> {
        match key {
            Some(k) if !k.is_empty() => Ok(ApiAuth::Keyed(Sha256::digest(k.as_bytes()).into())),
            _ if allow_open => Ok(ApiAuth::Open),
            _ => Err(ConfigError::MissingInternalKey),
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(self, ApiAuth::Open)
    }

    pub fn check(&self, headers: &HeaderMap) -> bool {
        match self {
            ApiAuth::Open => true,
            ApiAuth::Keyed(want) => {
                let got = headers.get("x-internal-key").map(|v| v.as_bytes()).unwrap_or(b"");
                let hg = Sha256::digest(got);
                // A missing header hashes the empty string and cannot equal the key's
                // hash; the comparison still runs, so absence costs the same time.
                hg.as_slice().ct_eq(want.as_slice()).into()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Who is the client? (TRUSTED_PROXIES)
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

fn canon(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

impl Cidr {
    /// `1.2.3.4`, `10.0.0.0/8`, `::1`, `fd00::/8`. A bare address is a /32 or /128.
    pub fn parse(s: &str) -> Result<Cidr, String> {
        let s = s.trim();
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().map_err(|_| format!("not an IP address: {:?}", a))?;
        let addr = canon(addr);
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            None => max,
            Some(p) => {
                let v: u8 = p.parse().map_err(|_| format!("bad prefix length: {:?}", p))?;
                // an IPv4-mapped IPv6 network such as ::ffff:10.0.0.0/104 is written as v4/8
                if v > max {
                    return Err(format!("prefix /{} is longer than {} bits", v, max));
                }
                v
            }
        };
        Ok(Cidr { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, canon(ip)) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix as u32) };
                (u32::from(n) & mask) == (u32::from(a) & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix as u32) };
                (u128::from(n) & mask) == (u128::from(a) & mask)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<Cidr>);

impl TrustedProxies {
    pub fn none() -> Self {
        TrustedProxies(Vec::new())
    }

    /// Comma-separated list; empty entries are ignored; any bad entry is an error
    /// (a typo must not silently turn into "trust nobody" or, worse, "trust somebody else").
    pub fn parse(s: &str) -> Result<Self, String> {
        let mut v = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            v.push(Cidr::parse(part)?);
        }
        Ok(TrustedProxies(v))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }
}

/// The client's address.
///
/// * The socket peer is the answer unless the peer is a trusted proxy.
/// * From a trusted peer: the rightmost `X-Forwarded-For` entry that is not itself
///   a trusted proxy. Entries to its left were written by the client or by hops
///   nobody vouches for, so they are never read.
/// * Anything that is not a plain IP address in that walk (a port, a name, junk)
///   ends it with the peer's address: a proxy appends addresses it saw on a socket,
///   so a non-address is not something to guess about.
pub fn client_ip(headers: &HeaderMap, peer: SocketAddr, trusted: &TrustedProxies) -> IpAddr {
    let peer_ip = canon(peer.ip());
    if !trusted.is_trusted(peer_ip) {
        return peer_ip;
    }
    let mut chain: Vec<&str> = Vec::new();
    for v in headers.get_all("x-forwarded-for") {
        match v.to_str() {
            Ok(s) => chain.extend(s.split(',')),
            Err(_) => return peer_ip,
        }
    }
    for entry in chain.iter().rev() {
        match entry.trim().parse::<IpAddr>() {
            Ok(ip) => {
                let ip = canon(ip);
                if !trusted.is_trusted(ip) {
                    return ip;
                }
            }
            Err(_) => return peer_ip,
        }
    }
    peer_ip
}

/// The string to store in `users.last_ip`: the canonical spelling of the address,
/// and for IPv4 only if the shared Exsecutor gate (`admitte_ipv4`, the same one the
/// root watchdog applies before it builds an nft rule) admits it.
pub fn ip_for_storage(ip: IpAddr) -> Option<String> {
    let ip = canon(ip);
    let s = ip.to_string();
    if ip.is_ipv4() && gate::admitte_ipv4(&s).is_err() {
        warn!(event = "last_ip_rejected", ip = %s, "client address not admitted by admitte_ipv4; not stored");
        return None;
    }
    Some(s)
}

// ---------------------------------------------------------------------------
// Cookies
// ---------------------------------------------------------------------------
/// Every value of the cookie `name` in every `Cookie` header, in order.
pub fn cookie_values<'a>(headers: &'a HeaderMap, name: &str) -> Vec<&'a str> {
    let prefix = format!("{}=", name);
    let mut out = Vec::new();
    for h in headers.get_all(header::COOKIE) {
        if let Ok(s) = h.to_str() {
            for part in s.split(';') {
                if let Some(v) = part.trim().strip_prefix(prefix.as_str()) {
                    out.push(v);
                }
            }
        }
    }
    out
}

/// Session ids in the request that have the shape of one (64 ASCII alphanumerics).
/// Nothing that fails the gate is ever used as a Redis key.
pub fn session_ids(headers: &HeaderMap) -> Vec<&str> {
    cookie_values(headers, "session").into_iter().filter(|s| valid_session_id(s)).collect()
}

pub const OAUTH_STATE_COOKIE: &str = "oauth_state";

pub fn session_cookie(session_id: &str, max_age: i64, secure: bool) -> HeaderValue {
    let cookie = format!(
        "session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
        session_id,
        max_age,
        if secure { "; Secure" } else { "" }
    );
    HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""))
}

pub fn clear_session_cookie(secure: bool) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        if secure { "; Secure" } else { "" }
    ))
    .unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// Binds the OAuth flow to the browser that started it. SameSite=Lax is enough: the
/// callback is a top-level GET navigation from discord.com, which Lax cookies ride on.
pub fn oauth_state_cookie(state: &str, max_age: i64, secure: bool) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{}={}; Path=/auth; HttpOnly; SameSite=Lax; Max-Age={}{}",
        OAUTH_STATE_COOKIE,
        state,
        max_age,
        if secure { "; Secure" } else { "" }
    ))
    .unwrap_or_else(|_| HeaderValue::from_static(""))
}

pub fn clear_oauth_state_cookie(secure: bool) -> HeaderValue {
    oauth_state_cookie("", 0, secure)
}

// ---------------------------------------------------------------------------
// Response headers
// ---------------------------------------------------------------------------
/// nosniff, frame denial, no referrer, no caching; HSTS only when the service is
/// configured as https (sending it over http is ignored by browsers, and a wrong
/// guess would pin a plain-http deployment to https).
///
/// No Content-Security-Policy is sent: the page template is not in this repository, so
/// whether it uses inline script or style is not known here. [OPEN]
pub async fn security_headers(State(hsts): State<bool>, req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    let set = |h: &mut HeaderMap, name: HeaderName, v: &'static str| {
        h.entry(name).or_insert(HeaderValue::from_static(v));
    };
    set(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(h, header::X_FRAME_OPTIONS, "DENY");
    set(h, header::REFERRER_POLICY, "no-referrer");
    set(h, header::CACHE_CONTROL, "no-store");
    if hsts {
        set(h, header::STRICT_TRANSPORT_SECURITY, "max-age=31536000");
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use std::net::Ipv4Addr;

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        h
    }
    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    // ---- I4: client address ---------------------------------------------------
    #[test]
    fn default_trusts_nobody_so_xff_is_ignored() {
        let none = TrustedProxies::none();
        let h = hm(&[("x-forwarded-for", "8.8.8.8")]);
        assert_eq!(client_ip(&h, sa("203.0.113.7:5555"), &none), ip("203.0.113.7"));
        let h = hm(&[("x-forwarded-for", "1.2.3.4; flush ruleset")]);
        assert_eq!(client_ip(&h, sa("203.0.113.7:5555"), &none), ip("203.0.113.7"));
    }

    #[test]
    fn untrusted_peer_cannot_use_xff_even_when_a_trusted_proxy_is_configured() {
        let tp = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let h = hm(&[("x-forwarded-for", "8.8.8.8")]);
        assert_eq!(client_ip(&h, sa("203.0.113.7:1"), &tp), ip("203.0.113.7"));
    }

    #[test]
    fn trusted_peer_gives_the_rightmost_untrusted_entry() {
        let tp = TrustedProxies::parse("10.0.0.0/8, 192.168.1.1").unwrap();
        // client spoofs "6.6.6.6", the edge proxy appends the real client 198.51.100.9,
        // an inner proxy 10.0.0.5 appends itself
        let h = hm(&[("x-forwarded-for", "6.6.6.6, 198.51.100.9, 10.0.0.5")]);
        assert_eq!(client_ip(&h, sa("10.0.0.2:80"), &tp), ip("198.51.100.9"));
        // spread over two header lines
        let h = hm(&[("x-forwarded-for", "6.6.6.6"), ("x-forwarded-for", "198.51.100.9, 192.168.1.1")]);
        assert_eq!(client_ip(&h, sa("10.0.0.2:80"), &tp), ip("198.51.100.9"));
    }

    #[test]
    fn trusted_peer_without_a_usable_xff_is_the_peer() {
        let tp = TrustedProxies::parse("10.0.0.0/8").unwrap();
        assert_eq!(client_ip(&HeaderMap::new(), sa("10.1.1.1:1"), &tp), ip("10.1.1.1"));
        let h = hm(&[("x-forwarded-for", "10.2.2.2, 10.3.3.3")]);
        assert_eq!(client_ip(&h, sa("10.1.1.1:1"), &tp), ip("10.1.1.1"), "all hops trusted");
        for junk in ["not-an-ip", "1.2.3.4:5678", "1.2.3.4; drop", "", "unknown", "1.2.3", "0x7f.1", "[::1]"] {
            let h = hm(&[("x-forwarded-for", &format!("8.8.8.8, {junk}"))]);
            assert_eq!(client_ip(&h, sa("10.1.1.1:1"), &tp), ip("10.1.1.1"), "rightmost entry {junk:?}");
        }
    }

    #[test]
    fn ipv4_mapped_v6_peers_and_entries_are_canonical() {
        let tp = TrustedProxies::parse("10.0.0.0/8").unwrap();
        assert_eq!(client_ip(&HeaderMap::new(), sa("[::ffff:203.0.113.7]:1"), &TrustedProxies::none()), ip("203.0.113.7"));
        let h = hm(&[("x-forwarded-for", "::ffff:198.51.100.9")]);
        assert_eq!(client_ip(&h, sa("[::ffff:10.0.0.1]:1"), &tp), ip("198.51.100.9"));
    }

    #[test]
    fn cidr_parsing_and_matching() {
        assert!(Cidr::parse("10.0.0.0/8").unwrap().contains(ip("10.255.255.255")));
        assert!(!Cidr::parse("10.0.0.0/8").unwrap().contains(ip("11.0.0.0")));
        assert!(Cidr::parse("1.2.3.4").unwrap().contains(ip("1.2.3.4")));
        assert!(!Cidr::parse("1.2.3.4").unwrap().contains(ip("1.2.3.5")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("203.0.113.1")));
        assert!(!Cidr::parse("0.0.0.0/0").unwrap().contains(ip("::1")), "families do not mix");
        assert!(Cidr::parse("172.16.0.0/12").unwrap().contains(ip("172.31.9.9")));
        assert!(!Cidr::parse("172.16.0.0/12").unwrap().contains(ip("172.32.0.0")));
        assert!(Cidr::parse("fd00::/8").unwrap().contains(ip("fdab::1")));
        assert!(!Cidr::parse("fd00::/8").unwrap().contains(ip("fe80::1")));
        assert!(Cidr::parse("::1").unwrap().contains(ip("::1")));
        assert!(Cidr::parse("10.0.0.1/33").is_err());
        assert!(Cidr::parse("::1/129").is_err());
        assert!(Cidr::parse("10.0.0.1/x").is_err());
        assert!(Cidr::parse("example.com").is_err());
        assert!(TrustedProxies::parse("10.0.0.0/8, bogus").is_err(), "a typo is an error, not 'trust nobody'");
        assert!(TrustedProxies::parse("").unwrap().is_empty());
        assert!(TrustedProxies::parse(" , ,").unwrap().is_empty());
    }

    #[test]
    fn what_is_stored_is_canonical_and_gate_admitted() {
        assert_eq!(ip_for_storage(ip("203.0.113.7")).as_deref(), Some("203.0.113.7"));
        assert_eq!(ip_for_storage(ip("::ffff:203.0.113.7")).as_deref(), Some("203.0.113.7"));
        assert_eq!(ip_for_storage(ip("2001:db8::1")).as_deref(), Some("2001:db8::1"));
        // every IPv4 spelling `IpAddr` can print is canonical, hence admitted by the gate
        for a in [0u32, 1, 255, 0x7f000001, 0x0a000001, 0xc0a80101, u32::MAX, 0x01020304, 0x08080808] {
            let s = ip_for_storage(IpAddr::V4(Ipv4Addr::from(a))).expect("admitted");
            assert!(gate::admitte_ipv4(&s).is_ok(), "{s}");
        }
    }

    // ---- I2: the internal key -----------------------------------------------------
    #[test]
    fn no_key_is_a_startup_error_unless_explicitly_opened() {
        assert_eq!(ApiAuth::from_config(None, false), Err(ConfigError::MissingInternalKey));
        assert_eq!(ApiAuth::from_config(Some(""), false), Err(ConfigError::MissingInternalKey));
        assert_eq!(ApiAuth::from_config(None, true), Ok(ApiAuth::Open));
        assert_eq!(ApiAuth::from_config(Some(""), true), Ok(ApiAuth::Open));
        assert!(matches!(ApiAuth::from_config(Some("k"), false), Ok(ApiAuth::Keyed(_))));
        // a key wins over the open flag
        assert!(matches!(ApiAuth::from_config(Some("k"), true), Ok(ApiAuth::Keyed(_))));
    }

    #[test]
    fn keyed_api_rejects_missing_wrong_and_near_miss_keys() {
        let a = ApiAuth::from_config(Some("s3cret-key-value"), false).unwrap();
        assert!(a.check(&hm(&[("x-internal-key", "s3cret-key-value")])));
        assert!(!a.check(&HeaderMap::new()));
        assert!(!a.check(&hm(&[("x-internal-key", "")])));
        assert!(!a.check(&hm(&[("x-internal-key", "s3cret-key-valuE")])));
        assert!(!a.check(&hm(&[("x-internal-key", "s3cret-key-value ")])));
        assert!(!a.check(&hm(&[("x-internal-key", "s3cret-key-valu")])));
        assert!(!a.check(&hm(&[("authorization", "Bearer s3cret-key-value")])));
        assert!(ApiAuth::Open.check(&HeaderMap::new()));
    }

    // ---- I9: names, sanitising ----------------------------------------------------
    #[test]
    fn usernames_are_ascii_only() {
        assert!(validate_username("alice_99-x").is_ok());
        assert!(validate_username("\u{430}dmin").is_err());
        assert!(validate_username("ab").is_err());
        assert!(validate_username(&"a".repeat(33)).is_err());
        assert!(validate_username("a b").is_err());
        assert!(validate_username("名前です").is_err());
    }

    #[test]
    fn passwords_have_both_bounds() {
        assert!(validate_password("1234567").is_err());
        assert!(validate_password("12345678").is_ok());
        assert!(validate_password(&"p".repeat(256)).is_ok());
        assert!(validate_password(&"p".repeat(257)).is_err());
    }

    #[test]
    fn discord_names_become_admitted_usernames() {
        for raw in ["alice", "Al!ce", "名前です", "", "a", "ab", "x".repeat(80).as_str(), "\u{430}dmin", "a b c", "--", "_.-_"] {
            let u = sanitize_discord_username(raw, "123456789012345678");
            assert!(gate::admitte_nomen(&u).is_ok(), "{raw:?} -> {u:?}");
        }
        assert_eq!(sanitize_discord_username("Al!ce", "1"), "Alce");
        assert_eq!(sanitize_discord_username("名前です", "42"), "discord_42");
        assert_eq!(sanitize_discord_username("ab", "42"), "discord_42");
        assert_eq!(sanitize_discord_username(&"x".repeat(80), "42"), "x".repeat(32));
        assert_eq!(sanitize_discord_username("", "12345678901234567890123"), "discord_12345678901234567890");
    }

    #[test]
    fn suffixed_names_stay_within_32_bytes_and_stay_admitted() {
        let base = "x".repeat(32);
        assert_eq!(username_with_suffix(&base, 0), base);
        for n in [1u32, 9, 10, 99, 100, 1000] {
            let u = username_with_suffix(&base, n);
            assert!(u.len() <= 32 && gate::admitte_nomen(&u).is_ok(), "{u}");
            assert!(u.ends_with(&format!("_{n}")));
        }
        assert_eq!(username_with_suffix("bob", 2), "bob_2");
    }

    #[test]
    fn snowflakes() {
        assert!(valid_discord_id("123456789012345678"));
        assert!(!valid_discord_id(""));
        assert!(!valid_discord_id("12a"));
        assert!(!valid_discord_id(&"1".repeat(21)));
        assert!(!valid_discord_id("-1"));
    }

    // ---- cookies ----------------------------------------------------------------------
    #[test]
    fn only_gate_admitted_session_ids_are_returned() {
        let good = "a".repeat(64);
        let h = hm(&[("cookie", &format!("theme=dark; session={good}; session=short; session={}", "b".repeat(65)))]);
        assert_eq!(session_ids(&h), vec![good.as_str()]);
        let h = hm(&[("cookie", "session=../../etc"), ("cookie", &format!("session={good}"))]);
        assert_eq!(session_ids(&h), vec![good.as_str()]);
        assert!(session_ids(&HeaderMap::new()).is_empty());
        assert_eq!(cookie_values(&hm(&[("cookie", "oauth_state=abc; x=y")]), "oauth_state"), vec!["abc"]);
    }

    #[test]
    fn cookie_attributes() {
        let c = session_cookie(&"a".repeat(64), 100, true);
        let s = c.to_str().unwrap();
        assert!(s.contains("HttpOnly") && s.contains("SameSite=Lax") && s.contains("Secure"));
        let c = oauth_state_cookie("abc", 600, false);
        let s = c.to_str().unwrap();
        assert!(s.starts_with("oauth_state=abc;") && s.contains("HttpOnly") && s.contains("SameSite=Lax") && !s.contains("Secure"));
        assert!(clear_session_cookie(false).to_str().unwrap().contains("Max-Age=0"));
    }

    #[test]
    fn ct_eq_str_basic() {
        assert!(ct_eq_str(b"abc", b"abc"));
        assert!(!ct_eq_str(b"abc", b"abd"));
        assert!(!ct_eq_str(b"abc", b"abcd"));
        assert!(ct_eq_str(b"", b""));
    }
}
