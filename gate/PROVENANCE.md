# Provenance of gate/

The gate is written in Exsecutor (a Latin-keyword systems language) and
compiled to C by `exsc aedifica --emitte c`. The emitted C is vendored here so
that building DCF-ID needs only a C11 compiler: no `fasmg`, no `exsc`.
Nothing under `gate/` except `glue.c` and `glue.h` and this file was written
by hand; `scripts/check-gate-fresh.sh` re-emits and compares.

- Exsecutor commit that last touched the two sources:
  `4d9c536c738df27f279898fb32085757aaec500b`
  (checkout HEAD when vendored: `c817af0fd7bd08e108827956115bd163e0dfe880`)
- Vendored on: 2026-10-09
- Command line (the shared network gate FIRST, then this one; one C unit):

      exsc aedifica --hospes x86_64-linux --emitte c   examples/dcf_net_gate/dcf_net_gate.exsc examples/dcfid_gate/dcfid_gate.exsc -o gate/dcfid_gate.gen.c
      exsc aedifica --hospes x86_64-linux --emitte h   (same sources)                                                            -o gate/dcfid_gate.gen.h
      exsc aedifica --hospes x86_64-linux --emitte rs  (same sources)                                                            -o gate/dcfid_gate.gen.rs

- sha256 of the compiler binary used (`build/exsc`): `2196c34746c1fa1f68330bb84a3bdbd09f199024a86def3c967f3ddbf1931731`
  (this file's digests below are what is machine-checked; the compiler digest is
  recorded, not re-derivable without rebuilding Exsecutor at that commit)

## Digests (checked by scripts/check-gate-fresh.sh)

Sources, in the Exsecutor checkout (checked when one is available):

```
1e8694c9ecb6eec723ca347f51b2f33f12c4042b642efd2df5dc16bb1ec7df7a  exsecutor:examples/dcf_net_gate/dcf_net_gate.exsc
77ff50c5044ca2a7a2eea214f3297ae713b32919d168d49e2f4c66d3ad240d5f  exsecutor:examples/dcfid_gate/dcfid_gate.exsc
96e3353a8e4287a54b3b2c54a576544c69ece77b9b7f3c00871b048635502162  exsecutor:examples/dcfid_gate/README.md
7e2407cf8200003337bd11bba5984c2f2cddda92be0872209342b5821c8de71c  exsecutor:examples/abortus/tutela.c
3b4184a404d40ca9101013e3eaf84e852e21f4301815a8989ce9a53e7142a0e4  exsecutor:examples/abortus/tutela.h
```

Vendored files, in this repository (always checked):

```
ffbbedf76c9239587a19d03107c9802d3e4e22f03ed9bb00e05c9d20e6efd6be  gate/dcfid_gate.gen.c
58c212453a72c86eaa0d7ab4366e870566d11b11936ed63cd845dab9bff3b872  gate/dcfid_gate.gen.h
19b3382fc571215c08339276d9d9e882f4b50e65f359ef1bfefbb19c595b77cb  gate/dcfid_gate.gen.rs
7e2407cf8200003337bd11bba5984c2f2cddda92be0872209342b5821c8de71c  gate/tutela.c
3b4184a404d40ca9101013e3eaf84e852e21f4301815a8989ce9a53e7142a0e4  gate/tutela.h
98a15082ea1d9befe35322b293de3b9c569591d0cc7f420ab8b975cc4eb1728a  gate/ANCHORS.md
9900cd9bdeacb4fd0924ea32b0acbb6473f0e09f2b816fdd00e7183f805f91f8  gate/glue.c
9703ec490e99b82f314d540401eaae4d7bc3c72a57f8da6e874266ab8af3dcc7  gate/glue.h
```

`glue.c` and `glue.h` are listed so that an edit to them shows up in review;
they are hand-written, not emitted.

## What each file is

| file | what |
|---|---|
| `dcfid_gate.gen.c` | the emitted C unit: `dcf_net_gate` (IPv4, port, interval) and `dcfid_gate` (username, session id / token, cents, Stripe-Signature shape) |
| `dcfid_gate.gen.h` | its generated C face |
| `dcfid_gate.gen.rs` | its generated Rust face (kept for reference and for the freshness check; src/gate.rs calls the glue, not these externs) |
| `tutela.c`, `tutela.h` | Exsecutor's `examples/abortus` guard, byte-identical: makes a trap return to a setjmp guard instead of ending the process |
| `glue.c`, `glue.h` | hand-written: one thunk per gate function, each run under a tutela guard |
| `ANCHORS.md` | the gate README's anchors table; `cargo test --lib` holds src/gate.rs to it |

## Trap policy and thread-safety

The gates are total (the Exsecutor-side corpus includes a no-trap sweep), so a
trap should be unreachable. If one happens anyway, `exsrt_abortus` returns to
the guard opened in `glue.c` and the Rust wrapper treats the call as a refusal
(fail closed, logged at error level). Without a guard `tutela.c` prints and
`abort()`s; every call in this crate is guarded.

Is the guard thread-safe? Read from `tutela.c`: the guard chain (`summa`) and
the depth counter (`profunditas`) are `static _Thread_local`, and `exsrt_abortus`
long-jumps only to a guard on its own thread's chain. The service is
multi-threaded (tokio) and calls the gate from async handlers, but never holds
a guard across an `.await`: the whole call is one synchronous FFI call, so a
guard is opened and closed on one thread, and between it and a trap there are
only C frames (tutela.h precondition P1). `cargo test --lib` exercises the trap
path from 8 threads at once (`gate::tests::trap_returns_to_the_guard_on_every_thread`).
That is a test of the mechanism with an injected trap, not a proof; the
soundness argument is in `examples/abortus/README.md` in Exsecutor.

## Licence

**Pending owner decision.** The `.exsc` sources are GPL-3.0-or-later.
Exsecutor's LICENSE.EXCEPTION (Exception A) frees only the compiler's own
contribution to emitted C, not the author's logic expressed in the source, and
this repository's README says BSD-3-Clause while Cargo.toml says
`Proprietary`. Shipping the emitted `dcfid_gate.gen.c` and `tutela.c` here
needs a relicensing grant of the kind LICENSE.GRANTS GRANT 1 gives for custos
-- not made, and not this change's to make. Until then this directory is
vendored for evaluation.
