// ============================================================================
// The Exsecutor gate, as seen from Rust.
// ============================================================================
// gate/dcfid_gate.gen.c is C emitted by `exsc` from examples/dcf_net_gate and
// examples/dcfid_gate (see gate/PROVENANCE.md). Each gate judges untrusted
// bytes and answers 0 (admitted) or the number of the first check that failed.
//
// This module is the only place that calls them, and it is safe code around
// two unsafe FFI calls' worth of care:
//
//   * the gate reads a buffer of EXACTLY its declared capacity, so every call
//     copies the input into a zero-padded array of that size first; an input
//     longer than the capacity is copied only up to the capacity and its real
//     length is passed, which the gate answers (verdict 2) before it reads;
//   * every call runs under a trap guard (gate/glue.c, Exsecutor's tutela), so
//     a trap -- which the gates' no-trap sweeps say cannot happen -- comes back
//     as `Refusal::Trapped` and is treated as a refusal, never as an abort.
// ============================================================================
use tracing::error;

/// Why a gate refused: the first failing check's number (see the verdict
/// tables at the top of the .exsc, mirrored in gate/ANCHORS.md), or a trap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Code(u8),
    /// The gate trapped (kind). Unreachable by the gate's own tests; refused
    /// anyway, because the alternative would be to admit what could not be judged.
    Trapped(u32),
}

pub type Verdict = Result<(), Refusal>;

/// The bytes of a session id (genus 0, 64) or an access token / OAuth state (genus 1, 32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Genus {
    Session = 0,
    Token = 1,
}

pub const NOMEN_CAP: usize = 32;
pub const SIGNUM_CAP: usize = 64;
pub const FORMA_CAP: usize = 512;
pub const IPV4_CAP: usize = 16;

mod ffi {
    extern "C" {
        pub fn dcfid_glue_nomen(b: *mut u8, n: u64, out: *mut u64) -> u32;
        pub fn dcfid_glue_signum(b: *mut u8, n: u64, genus: u64, out: *mut u64) -> u32;
        pub fn dcfid_glue_summam(cents: u64, out: *mut u64) -> u32;
        pub fn dcfid_glue_forma(b: *mut u8, n: u64, out: *mut u64) -> u32;
        pub fn dcfid_glue_ipv4(b: *mut u8, n: u64, out: *mut u64) -> u32;
        pub fn dcfid_glue_selftest_trap(kind: u32) -> u32;
        pub fn dcfid_glue_depth() -> u32;
    }
}

/// Copy `input` into a zero-padded buffer of exactly N bytes.
fn padded<const N: usize>(input: &[u8]) -> [u8; N] {
    let mut buf = [0u8; N];
    let take = input.len().min(N);
    buf[..take].copy_from_slice(&input[..take]);
    buf
}

/// The gate that `raw` calls.
#[derive(Debug, Clone, Copy)]
pub enum Which {
    Nomen,
    Signum(u64),
    Summam,
    Forma,
    Ipv4,
}

/// The gate's verdict number for `input` with the length `n` handed to it
/// (`n` is `input.len()` everywhere except tests that lie about it), or
/// `Err(kind)` if it trapped. For `Which::Summam` the amount is `n` and
/// `input` is ignored.
pub fn raw(which: Which, input: &[u8], n: u64) -> Result<u64, u32> {
    let mut out = 0u64;
    // SAFETY: each buffer is a local array of exactly the capacity the gate
    // reads, alive for the whole call and never written by the gate; `out` is a
    // valid u64; the glue never retains a pointer past the call.
    let kind = unsafe {
        match which {
            Which::Nomen => {
                let mut b = padded::<NOMEN_CAP>(input);
                ffi::dcfid_glue_nomen(b.as_mut_ptr(), n, &mut out)
            }
            Which::Signum(genus) => {
                let mut b = padded::<SIGNUM_CAP>(input);
                ffi::dcfid_glue_signum(b.as_mut_ptr(), n, genus, &mut out)
            }
            Which::Summam => ffi::dcfid_glue_summam(n, &mut out),
            Which::Forma => {
                let mut b = padded::<FORMA_CAP>(input);
                ffi::dcfid_glue_forma(b.as_mut_ptr(), n, &mut out)
            }
            Which::Ipv4 => {
                let mut b = padded::<IPV4_CAP>(input);
                ffi::dcfid_glue_ipv4(b.as_mut_ptr(), n, &mut out)
            }
        }
    };
    if kind == 0 {
        Ok(out)
    } else {
        Err(kind)
    }
}

fn verdict(which: Which, name: &'static str, input: &[u8], n: u64) -> Verdict {
    match raw(which, input, n) {
        Ok(0) => Ok(()),
        Ok(code) => Err(Refusal::Code(code as u8)),
        Err(kind) => {
            error!(gate = name, kind, "gate trapped; refusing");
            Err(Refusal::Trapped(kind))
        }
    }
}

/// A username: 3..=32 bytes of `[A-Za-z0-9_-]`.
pub fn admitte_nomen(s: &str) -> Verdict {
    verdict(Which::Nomen, "nomen", s.as_bytes(), s.len() as u64)
}

/// A session id (exactly 64) or an access token / OAuth state (exactly 32), `[A-Za-z0-9]` only.
pub fn admitte_signum(s: &str, genus: Genus) -> Verdict {
    verdict(Which::Signum(genus as u64), "signum", s.as_bytes(), s.len() as u64)
}

/// An amount in US cents: 250..=10000.
pub fn admitte_summam(cents: u64) -> Verdict {
    verdict(Which::Summam, "summam", &[], cents)
}

/// The shape of a Stripe-Signature header (not its truth).
pub fn admitte_formam_signaturae(s: &str) -> Verdict {
    verdict(Which::Forma, "forma", s.as_bytes(), s.len() as u64)
}

/// A canonical dotted-quad IPv4 address (the shared dcf_net_gate).
pub fn admitte_ipv4(s: &str) -> Verdict {
    verdict(Which::Ipv4, "ipv4", s.as_bytes(), s.len() as u64)
}

/// Test hook: trap inside a guard, return the kind the guard saw.
pub fn selftest_trap(kind: u32) -> u32 {
    // SAFETY: no pointers; the glue opens and closes its own guard.
    unsafe { ffi::dcfid_glue_selftest_trap(kind) }
}

/// Guards the calling thread has open (0 outside a call).
pub fn guard_depth() -> u32 {
    // SAFETY: no pointers.
    unsafe { ffi::dcfid_glue_depth() }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the gate README's anchors, parsed from the vendored copy -----------
    // `| fn | `input` | n | verdict |` rows between the anchors markers. The
    // same table is parsed by Exsecutor's proba.py against the gate itself.
    fn unescape(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\\' && i + 1 < b.len() && b[i + 1] == b'\\' {
                out.push(b'\\');
                i += 2;
            } else if b[i] == b'\\' && i + 3 < b.len() && b[i + 1] == b'x' {
                out.push(u8::from_str_radix(&s[i + 2..i + 4], 16).unwrap());
                i += 4;
            } else if b[i] == b'{' {
                let close = s[i..].find('}').expect("unclosed {c*N}") + i;
                let inner = &s[i + 1..close];
                let star = inner.rfind('*').expect("{c*N} without *");
                let (ch, cnt) = (&inner[..star], inner[star + 1..].parse::<usize>().unwrap());
                let unit = if ch.starts_with("\\x") {
                    vec![u8::from_str_radix(&ch[2..4], 16).unwrap()]
                } else {
                    ch.as_bytes().to_vec()
                };
                for _ in 0..cnt {
                    out.extend_from_slice(&unit);
                }
                i = close + 1;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        out
    }

    fn anchors() -> Vec<(String, Vec<u8>, u64, u64)> {
        let text = include_str!("../gate/ANCHORS.md");
        let mut on = false;
        let mut rows = Vec::new();
        for line in text.lines() {
            if line.contains("<!-- anchors:begin -->") {
                on = true;
                continue;
            }
            if line.contains("<!-- anchors:end -->") {
                break;
            }
            if !on || !line.starts_with('|') {
                continue;
            }
            let cells: Vec<&str> = line.trim().trim_matches('|').split('|').map(|c| c.trim()).collect();
            if cells.len() != 4 || cells[0] == "fn" || cells[0].starts_with("---") {
                continue;
            }
            let inp = cells[1].trim_matches('`');
            let bytes = unescape(inp);
            let n = if cells[2] == "=" { bytes.len() as u64 } else { cells[2].parse().unwrap() };
            rows.push((cells[0].to_string(), bytes, n, cells[3].parse().unwrap()));
        }
        rows
    }

    fn call(fn_name: &str, bytes: &[u8], n: u64) -> Result<u64, u32> {
        match fn_name {
            "nomen" => raw(Which::Nomen, bytes, n),
            "forma" => raw(Which::Forma, bytes, n),
            "summam" => {
                let cents: u64 = std::str::from_utf8(bytes).unwrap().parse().unwrap();
                raw(Which::Summam, &[], cents)
            }
            s if s.starts_with("signum:") => raw(Which::Signum(s[7..].parse().unwrap()), bytes, n),
            other => panic!("unknown anchor fn {other}"),
        }
    }

    #[test]
    fn wrapper_matches_every_readme_anchor() {
        let rows = anchors();
        assert!(rows.len() >= 80, "only {} anchors parsed from gate/ANCHORS.md", rows.len());
        for (f, bytes, n, want) in &rows {
            let got = call(f, bytes, *n).unwrap_or_else(|k| panic!("{f} trapped (kind {k})"));
            assert_eq!(got, *want, "anchor {f} {:?} n={n}", String::from_utf8_lossy(bytes));
        }
        // every verdict class of every table occurs among the anchors
        for (f, codes) in [
            ("nomen", vec![0u64, 1, 2, 3, 4]),
            ("signum:0", vec![0, 2, 3]),
            ("signum:2", vec![1]),
            ("summam", vec![0, 1, 2]),
            ("forma", (0..=9).collect()),
        ] {
            for c in codes {
                assert!(rows.iter().any(|r| r.0 == f && r.3 == c), "no anchor for {f} verdict {c}");
            }
        }
    }

    // ---- the typed wrappers, one assertion per verdict class ----------------
    fn code(v: Verdict) -> u8 {
        match v {
            Ok(()) => 0,
            Err(Refusal::Code(c)) => c,
            Err(Refusal::Trapped(k)) => panic!("trapped {k}"),
        }
    }

    #[test]
    fn nomen_classes() {
        assert_eq!(code(admitte_nomen("alice")), 0);
        assert_eq!(code(admitte_nomen("a-b_C9")), 0);
        assert_eq!(code(admitte_nomen("")), 1);
        assert_eq!(code(admitte_nomen(&"a".repeat(33))), 2);
        assert_eq!(code(admitte_nomen(&"a".repeat(32))), 0);
        assert_eq!(code(admitte_nomen("ab")), 3);
        assert_eq!(code(admitte_nomen("a b")), 4);
        assert_eq!(code(admitte_nomen("\u{430}dmin")), 4, "Cyrillic a is not ASCII");
        assert_eq!(code(admitte_nomen("\u{663}\u{663}\u{663}")), 4, "Arabic-Indic digits");
        assert_eq!(code(admitte_nomen("al\0ce")), 4);
        assert_eq!(code(admitte_nomen("alice\n")), 4);
    }

    #[test]
    fn signum_classes() {
        let id = "a".repeat(64);
        let tok = "Z".repeat(32);
        assert_eq!(code(admitte_signum(&id, Genus::Session)), 0);
        assert_eq!(code(admitte_signum(&tok, Genus::Token)), 0);
        assert_eq!(code(admitte_signum(&tok, Genus::Session)), 2);
        assert_eq!(code(admitte_signum(&id, Genus::Token)), 2);
        assert_eq!(code(admitte_signum("", Genus::Token)), 2);
        assert_eq!(code(admitte_signum(&format!("{}-", "a".repeat(31)), Genus::Token)), 3);
        assert_eq!(code(admitte_signum(&"a".repeat(1000), Genus::Session)), 2);
        // an unknown genus is refused before the length is looked at
        assert_eq!(raw(Which::Signum(2), b"x", 1), Ok(1));
        assert_eq!(raw(Which::Signum(u64::MAX), b"x", 1), Ok(1));
    }

    #[test]
    fn summam_classes() {
        assert_eq!(code(admitte_summam(249)), 1);
        assert_eq!(code(admitte_summam(250)), 0);
        assert_eq!(code(admitte_summam(10000)), 0);
        assert_eq!(code(admitte_summam(10001)), 2);
        assert_eq!(code(admitte_summam(u64::MAX)), 2);
        assert_eq!(code(admitte_summam(0)), 1);
    }

    #[test]
    fn forma_classes() {
        let v = "0123456789abcdef".repeat(4);
        let ok = format!("t=1492774577,v1={v}");
        assert_eq!(code(admitte_formam_signaturae(&ok)), 0);
        assert_eq!(code(admitte_formam_signaturae(&format!("{ok},v0={v}"))), 0, "test-mode v0");
        assert_eq!(code(admitte_formam_signaturae(&format!("v1={v},t=1"))), 0, "order is free");
        assert_eq!(code(admitte_formam_signaturae("")), 1);
        assert_eq!(code(admitte_formam_signaturae(&"t".repeat(513))), 2);
        assert_eq!(code(admitte_formam_signaturae(&format!("{ok},x=1"))), 3);
        assert_eq!(code(admitte_formam_signaturae(&format!("t=,v1={v}"))), 4);
        assert_eq!(code(admitte_formam_signaturae(&format!("t=1,v1={}", &v[..63]))), 5);
        assert_eq!(code(admitte_formam_signaturae(&format!("t=1,v1={}", v.to_uppercase()))), 5);
        let seven_v = std::iter::repeat_n(format!("v1={v}"), 7).collect::<Vec<_>>().join(",");
        assert_eq!(code(admitte_formam_signaturae(&format!("t=1,{seven_v},x"))), 6);
        assert_eq!(code(admitte_formam_signaturae(&format!("t=1,t=2,v1={v}"))), 7);
        assert_eq!(code(admitte_formam_signaturae(&format!("v1={v}"))), 8);
        assert_eq!(code(admitte_formam_signaturae("t=1")), 9);
        assert_eq!(code(admitte_formam_signaturae(&format!("t=1,v0={v}"))), 9);
    }

    #[test]
    fn ipv4_is_the_shared_gate() {
        assert_eq!(code(admitte_ipv4("1.2.3.4")), 0);
        assert_eq!(code(admitte_ipv4("1.2.3.08")), 6);
        assert_eq!(code(admitte_ipv4("1.2.3.4; flush ruleset")), 2);
        assert_eq!(code(admitte_ipv4("::1")), 3);
        assert_eq!(code(admitte_ipv4("")), 1);
    }

    #[test]
    fn lying_lengths_are_answered_without_a_read() {
        // n far past the capacity: answered before any byte is read, input shorter than n
        for n in [33u64, 255, 1 << 32, 1 << 63, u64::MAX] {
            assert_eq!(raw(Which::Nomen, b"abc", n), Ok(2), "nomen n={n}");
            assert_eq!(raw(Which::Forma, b"t=1", n.max(513)), Ok(2), "forma n={n}");
            assert_eq!(raw(Which::Signum(0), b"abc", n.max(65)), Ok(2), "signum n={n}");
            assert_eq!(raw(Which::Ipv4, b"1.2.3.4", n.max(16)), Ok(2), "ipv4 n={n}");
        }
    }

    #[test]
    fn long_inputs_are_not_copied_whole_and_still_refused() {
        let big = "a".repeat(10_000_000);
        assert_eq!(code(admitte_nomen(&big)), 2);
        assert_eq!(code(admitte_signum(&big, Genus::Session)), 2);
        assert_eq!(code(admitte_formam_signaturae(&big)), 2);
    }

    #[test]
    fn no_trap_sweep_from_rust() {
        // every length 0..cap+5 over a few byte patterns, through the wrapper
        let patterns: [&[u8]; 5] = [b"a", b"\x00", b"\xff", b"t=,1v", b"0.9"];
        for pat in patterns {
            for len in 0..(FORMA_CAP + 6) {
                let data: Vec<u8> = pat.iter().cycle().take(len).copied().collect();
                for which in [Which::Nomen, Which::Signum(0), Which::Signum(1), Which::Signum(9), Which::Forma, Which::Ipv4] {
                    assert!(raw(which, &data, len as u64).is_ok(), "{which:?} trapped at len {len}");
                }
            }
        }
        for c in [0u64, 249, 250, 10000, 10001, 1 << 32, 1 << 63, u64::MAX] {
            assert!(raw(Which::Summam, &[], c).is_ok());
        }
    }

    // ---- the trap policy -----------------------------------------------------
    #[test]
    fn a_trap_returns_to_the_guard_instead_of_aborting() {
        assert_eq!(selftest_trap(1), 1);
        assert_eq!(selftest_trap(5), 5);
        assert_eq!(selftest_trap(0), 0xffff_ffff, "kind 0 must never read as success");
        assert_eq!(guard_depth(), 0, "the guard chain is restored");
    }

    #[test]
    fn trap_returns_to_the_guard_on_every_thread() {
        let handles: Vec<_> = (0..8u32)
            .map(|t| {
                std::thread::spawn(move || {
                    for i in 0..2000u32 {
                        let kind = 1 + (t + i) % 5;
                        assert_eq!(selftest_trap(kind), kind);
                        assert_eq!(guard_depth(), 0);
                        assert_eq!(code(admitte_nomen("alice")), 0);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("a gate thread panicked or aborted");
        }
    }
}
