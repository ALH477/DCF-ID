#!/usr/bin/env python3
"""Concurrent-login burst against a built dcf-id (adapted from the reviewer's g5_dos.py).

    DCFID_BIN=path/to/dcf-id python3 tests/poc/burst.py [--no-redis] [--only A,B]

The lockout used to be read at the START of a login and written at the END, and Argon2 ran on the async
worker thread, so a burst of N concurrent wrong logins all saw "not locked" and all paid for a full Argon2
verification. A request is now admitted by an atomic increment BEFORE any hashing (5 per client address, 20
per username), and Argon2 runs on a bounded blocking pool.

Each burst starts a fresh service (nothing carried over in Redis or in the in-process limiter) and fires N
requests from one barrier. "evaluated" = the page said "Invalid credentials", i.e. a verification (or the
dummy hash for an unknown user) ran and failed; "pre-rejected" = "Too many attempts", no hashing; "busy" =
HTTP 503. A binary that exposes `argon2_runs` on /metrics is also asked for its own count.

Needs the same scratch template as poc.py (it reads ERROR:/USER: markers); see that file's header.
Exit 1 if any check is [VULN].
"""
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Svc, Redis, text, INTERNAL_KEY  # noqa: E402

LIMIT = 5          # attempts per client address per window
RESULTS = []


def report(cid, name, verdict, detail=""):
    RESULTS.append((cid, verdict))
    print("%s %-4s %s%s" % ({"VULN": "[VULN]", "ok": "[ ok ]"}[verdict], cid, name, (" -- " + detail) if detail else ""), flush=True)


def classify(st, body):
    t = text(body)
    if st == 503:
        return "busy"
    if "Too many attempts" in t:
        return "pre-rejected"
    if "USER:" in t:
        return "success"
    if "Invalid credentials" in t:
        return "evaluated"
    return "other:%s" % st


def metric(s, name):
    st, _, d = s.api("GET", "/metrics")
    if st != 200:
        return None
    try:
        return json.loads(d).get(name)
    except ValueError:
        return None


def burst(s, N, fields):
    """N concurrent POST /auth/login released together; fields(i) -> form dict. Returns (counts, max latency, health latency)"""
    bar = threading.Barrier(N + 1)
    out = [None] * N
    lat = [0.0] * N

    def one(i):
        bar.wait()
        t = time.time()
        st, _, d = s.form("/auth/login", fields(i), timeout=240)
        lat[i] = time.time() - t
        out[i] = classify(st, d)

    ts = [threading.Thread(target=one, args=(i,)) for i in range(N)]
    [t.start() for t in ts]
    health = [None]

    def probe():
        time.sleep(0.10)
        t = time.time()
        st, _, _ = s.req("GET", "/health", timeout=240)
        health[0] = (time.time() - t, st)

    pt = threading.Thread(target=probe)
    pt.start()
    bar.wait()
    [t.join() for t in ts]
    pt.join()
    counts = {}
    for o in out:
        counts[o] = counts.get(o, 0) + 1
    return counts, max(lat), health[0]


def fresh(redis, name="victim1", pw="correct-horse-1"):
    if redis:
        redis.flush()
    s = Svc(redis).start()
    st, _, d = s.form("/auth/register", {"username": name, "password": pw})
    assert "USER:" in text(d), "could not register the test user: %s" % text(d)[:200]
    return s


def check_wrong_burst(redis, mode):
    for N in (30, 100):
        s = fresh(redis)
        try:
            counts, wall, health = burst(s, N, lambda i: {"username": "victim1", "password": "wrong-guess-%d" % i})
            ev = counts.get("evaluated", 0)
            runs = metric(s, "argon2_runs")
            detail = "%s; max login wall %.2fs; /health during the burst %.2fs (HTTP %s); server's own argon2_runs=%s" % (
                counts, wall, health[0], health[1], runs if runs is not None else "n/a (not exposed)")
            # the user was registered through the service, which ran 1 hash itself
            report("A%d" % N, "[%s] %d concurrent WRONG logins against one real user: at most %d may reach Argon2" % (mode, N, LIMIT),
                   "VULN" if ev > LIMIT else "ok", "%d of %d evaluated; %s" % (ev, N, detail))
        finally:
            s.stop()


def check_unknown_burst(redis, mode):
    s = fresh(redis)
    try:
        counts, wall, health = burst(s, 30, lambda i: {"username": "nosuchuser%d" % i, "password": "guess-%d-xxxx" % i})
        ev = counts.get("evaluated", 0)
        report("D30", "[%s] 30 concurrent logins naming 30 DIFFERENT unknown users (the dummy-hash path), one address" % mode,
               "VULN" if ev > LIMIT else "ok", "%d of 30 evaluated; %s" % (ev, counts))
    finally:
        s.stop()


def check_legit_concurrency(redis, mode):
    s = fresh(redis)
    try:
        counts, wall, health = burst(s, LIMIT, lambda i: {"username": "victim1", "password": "correct-horse-1"})
        ok = counts.get("success", 0)
        report("L%d" % LIMIT, "[%s] %d concurrent CORRECT logins by the real user all succeed (no false positive)" % (mode, LIMIT),
               "ok" if ok == LIMIT else "VULN", str(counts))
        # and nothing lingers: a sequential wrong guess is still just an ordinary failure, then the right one works
        st, _, d = s.form("/auth/login", {"username": "victim1", "password": "wrong-guess-zz"})
        st2, _, d2 = s.form("/auth/login", {"username": "victim1", "password": "correct-horse-1"})
        report("L2", "[%s] after that burst one wrong guess is an ordinary failure and the right password still works" % mode,
               "ok" if (classify(st, d) == "evaluated" and classify(st2, d2) == "success") else "VULN",
               "%s then %s" % (classify(st, d), classify(st2, d2)))
    finally:
        s.stop()


def check_locked_stays_locked(redis, mode):
    s = fresh(redis)
    try:
        for i in range(LIMIT):
            s.form("/auth/login", {"username": "victim1", "password": "wrong-guess-%d" % i})
        st, _, d = s.form("/auth/login", {"username": "victim1", "password": "correct-horse-1"})
        report("K1", "[%s] after %d wrong guesses even the right password is refused for the lockout window" % (mode, LIMIT),
               "ok" if classify(st, d) == "pre-rejected" else "VULN", classify(st, d))
    finally:
        s.stop()


def check_register_burst(redis, mode):
    s = Svc(redis).start()
    try:
        if redis:
            redis.flush()
        N = 40
        bar = threading.Barrier(N + 1)
        out = [None] * N

        def one(i):
            bar.wait()
            st, _, d = s.form("/auth/register", {"username": "bulkuser%02d" % i, "password": "correct-horse-1"}, timeout=240)
            t = text(d)
            out[i] = "success" if "USER:" in t else ("throttled" if "Too many registration" in t else ("busy" if st == 503 else "other"))

        ts = [threading.Thread(target=one, args=(i,)) for i in range(N)]
        [t.start() for t in ts]
        bar.wait()
        [t.join() for t in ts]
        c = {}
        for o in out:
            c[o] = c.get(o, 0) + 1
        report("R40", "[%s] 40 concurrent registrations from one address: at most 10 hash" % mode,
               "VULN" if c.get("success", 0) > 10 else "ok", str(c))
    finally:
        s.stop()


CHECKS = [("A", check_wrong_burst), ("D", check_unknown_burst), ("L", check_legit_concurrency),
          ("K", check_locked_stays_locked), ("R", check_register_burst)]


def main():
    only = None
    if "--only" in sys.argv:
        only = set(sys.argv[sys.argv.index("--only") + 1].split(","))
    modes = []
    redis = None
    if "--no-redis" not in sys.argv:
        try:
            redis = Redis()
            modes.append(("redis", redis))
        except FileNotFoundError:
            print("note: redis-server not found; running without it only", flush=True)
    modes.append(("no redis: in-process limiter", None))
    try:
        for mode, r in modes:
            for cid, fn in CHECKS:
                if only and cid not in only:
                    continue
                fn(r, mode)
    finally:
        if redis:
            redis.stop()
    bad = [r for r in RESULTS if r[1] == "VULN"]
    print("\n%d checks: %d ok, %d VULN" % (len(RESULTS), len(RESULTS) - len(bad), len(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
