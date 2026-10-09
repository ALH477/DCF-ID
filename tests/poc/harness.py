# Adapted from the independent reviewer's adversary harness (review-dcfid-v2/exploits/harness.py; the
# original is untouched). Launches the dcf-id release binary named by $DCFID_BIN with a throwaway SQLite
# DB and (optionally) a throwaway redis-server, speaks HTTP, reads the SQLite file back.
# Changes from the original: no hard-coded scratch path (the binary comes from $DCFID_BIN), constants
# otherwise as they were.
import http.client, json, os, socket, sqlite3, subprocess, tempfile, time, urllib.parse, shutil, threading

BIN = os.environ.get("DCFID_BIN")
if not BIN:
    raise SystemExit("set DCFID_BIN=/path/to/dcf-id (built from a scratch copy with a stub template)")
WH_SECRET = "whsec_adv_secret_value"
INTERNAL_KEY = "adv-internal-key-0123456789abcdef"
FREE_TIER = 134217728
GIB = 1073741824

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

class Redis:
    def __init__(self):
        exe = shutil.which("redis-server")
        if not exe: raise FileNotFoundError("redis-server")
        self.dir = tempfile.mkdtemp(prefix="adv-redis-")
        self.port = free_port()
        self.proc = subprocess.Popen(
            [exe, "--port", str(self.port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no", "--dir", self.dir],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try: self.cmd("PING"); return
            except OSError: time.sleep(0.05)
        raise RuntimeError("redis did not come up")
    def cmd(self, *args):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            out = b"*%d\r\n" % len(args)
            for a in args:
                a = a.encode() if isinstance(a, str) else a
                out += b"$%d\r\n%s\r\n" % (len(a), a)
            s.sendall(out); f = s.makefile("rb"); return self._r(f)
        finally: s.close()
    def _r(self, f):
        line = f.readline().rstrip(b"\r\n"); t, rest = line[:1], line[1:]
        if t in (b"+", b"-"): return rest.decode()
        if t == b":": return int(rest)
        if t == b"$":
            n = int(rest)
            if n < 0: return None
            return f.read(n + 2)[:-2].decode(errors="replace")
        if t == b"*": return [self._r(f) for _ in range(int(rest))]
        raise RuntimeError("bad RESP %r" % line)
    def flush(self): self.cmd("FLUSHALL")
    def stop(self):
        self.proc.terminate()
        try: self.proc.wait(3)
        except subprocess.TimeoutExpired: self.proc.kill()
        shutil.rmtree(self.dir, ignore_errors=True)

class Refused(Exception):
    def __init__(self, rc, log): super().__init__("exit %s" % rc); self.rc = rc; self.log = log

class Svc:
    def __init__(self, redis=None, key=INTERNAL_KEY, allow_open=False, extra_env=None, bin=None):
        self.bin = bin or BIN
        self.dir = tempfile.mkdtemp(prefix="adv-svc-")
        self.port = free_port()
        self.db = os.path.join(self.dir, "id.db")
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": self.dir,
            "DATABASE_URL": "sqlite:%s?mode=rwc" % self.db,
            "IDENTITY_PORT": str(self.port),
            "STRIPE_SECRET_KEY": "sk_test_adv",
            "STRIPE_WEBHOOK_SECRET": WH_SECRET,
            "DISCORD_CLIENT_ID": "adv-client",
            "DISCORD_CLIENT_SECRET": "adv-secret",
            "BASE_URL": "http://127.0.0.1:%d" % self.port,
            "REDIS_URL": "redis://127.0.0.1:%d" % (redis.port if redis else 1),
            "RUST_LOG": "warn",
            "NO_PROXY": "*", "no_proxy": "*",
        }
        if key is not None: env["DCF_ID_INTERNAL_KEY"] = key
        if allow_open: env["DCF_ID_ALLOW_OPEN_API"] = "1"
        env.update(extra_env or {})
        self.logf = open(os.path.join(self.dir, "service.log"), "wb")
        self.proc = subprocess.Popen([self.bin], cwd=self.dir, env=env, stdout=self.logf, stderr=subprocess.STDOUT)
    def start(self, wait=30):
        t0 = time.time()
        while time.time() - t0 < wait:
            rc = self.proc.poll()
            if rc is not None: raise Refused(rc, self.log())
            st, _, _ = self.req("GET", "/health", timeout=2)
            if st is not None: return self
            time.sleep(0.05)
        raise RuntimeError("did not listen: %s" % self.log())
    def log(self):
        self.logf.flush()
        try: return open(os.path.join(self.dir, "service.log"), errors="replace").read()[-3000:]
        except OSError: return ""
    def alive(self): return self.proc.poll() is None
    def rc(self): return self.proc.poll()
    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try: self.proc.wait(3)
            except subprocess.TimeoutExpired: self.proc.kill()
        self.logf.close(); shutil.rmtree(self.dir, ignore_errors=True)
    def req(self, method, path, headers=None, body=None, timeout=25, raw_headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        try:
            if raw_headers is not None:
                conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
                conn.putheader("Host", "127.0.0.1")
                for (k, v) in raw_headers: conn.putheader(k, v)
                if body is not None: conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
            else:
                conn.request(method, path, body=body, headers=headers or {})
            r = conn.getresponse(); data = r.read()
            hdrs = {k.lower(): v for k, v in r.getheaders()}
            hdrs["set-cookie-all"] = r.msg.get_all("Set-Cookie") or []
            return r.status, hdrs, data
        except (OSError, http.client.HTTPException) as e:
            return None, {"set-cookie-all": []}, repr(e).encode()
        finally:
            conn.close()
    def raw(self, raw_bytes, timeout=10):
        """Send fully attacker-controlled bytes on one socket; return the raw response bytes."""
        s = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        try:
            s.sendall(raw_bytes); s.settimeout(timeout)
            out = b""
            while True:
                try:
                    chunk = s.recv(65536)
                except socket.timeout:
                    break
                if not chunk: break
                out += chunk
                if len(out) > 2_000_000: break
            return out
        except OSError as e:
            return b"OSERR:" + repr(e).encode()
        finally:
            s.close()
    def form(self, path, fields, headers=None, **kw):
        h = {"Content-Type": "application/x-www-form-urlencoded"}; h.update(headers or {})
        body = fields if isinstance(fields, (bytes, str)) else urllib.parse.urlencode(fields)
        return self.req("POST", path, h, body.encode() if isinstance(body, str) else body, **kw)
    def api(self, method, path, key=INTERNAL_KEY, body=None, extra=None):
        h = {}
        if key is not None: h["X-Internal-Key"] = key
        if body is not None:
            h["Content-Type"] = "application/json"
            if isinstance(body, (bytes, bytearray)): pass
            elif isinstance(body, str): body = body.encode()
            else: body = json.dumps(body).encode()
        h.update(extra or {})
        return self.req(method, path, h, body)
    def sql(self, q, args=()):
        c = sqlite3.connect(self.db, timeout=20)
        try:
            cur = c.execute(q, args); rows = cur.fetchall(); c.commit(); return rows
        finally: c.close()
    def seed(self, username, token=None, pw_hash=None, discord_id=None, used=0, bal=0.0, vip=0, ip=None):
        import random, string
        token = token or "".join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
        self.sql("INSERT INTO users (username, password_hash, access_token, discord_id, data_used, account_balance,"
                 " last_reset_date, last_ip, last_seen, created_at, is_vip) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                 (username, pw_hash, token, discord_id, used, bal, "2026-01", ip, None, "2026-01-01T00:00:00Z", vip))
        return token
    def balance(self, token): return self.sql("SELECT account_balance FROM users WHERE access_token=?", (token,))[0][0]
    def used(self, token): return self.sql("SELECT data_used FROM users WHERE access_token=?", (token,))[0][0]

def text(d): return d.decode(errors="replace") if isinstance(d, (bytes, bytearray)) else d
