#!/usr/bin/env bash
# scripts/vendor-gate.sh -- regenerate gate/ from an Exsecutor checkout.
#
#   EXSECUTOR=/path/to/exsecutor scripts/vendor-gate.sh
#
# Needs $EXSECUTOR/build/exsc (built there with `make all`). Overwrites the
# emitted files, the tutela guard copy, ANCHORS.md and the machine-checked part
# of gate/PROVENANCE.md. The glue (gate/glue.c, gate/glue.h) is hand-written for
# this repository and is not touched. Consumers of this repository never run
# this: gate/ is committed, and building needs only a C11 compiler.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
ex="${EXSECUTOR:-${1:-}}"
[ -n "$ex" ] || { echo "vendor-gate: set EXSECUTOR=/path/to/exsecutor" >&2; exit 2; }
exsc="$ex/build/exsc"
[ -x "$exsc" ] || { echo "vendor-gate: $exsc missing -- run 'make all' in $ex" >&2; exit 2; }
net="$ex/examples/dcf_net_gate/dcf_net_gate.exsc"
unit="$ex/examples/dcfid_gate/dcfid_gate.exsc"
readme="$ex/examples/dcfid_gate/README.md"
for f in "$net" "$unit" "$readme" "$ex/examples/abortus/tutela.c" "$ex/examples/abortus/tutela.h"; do
  [ -f "$f" ] || { echo "vendor-gate: $f missing" >&2; exit 2; }
done

for k in c h rs; do
  "$exsc" aedifica --hospes x86_64-linux --emitte "$k" "$net" "$unit" -o "$root/gate/dcfid_gate.gen.$k" >/dev/null
done
cp "$ex/examples/abortus/tutela.c" "$ex/examples/abortus/tutela.h" "$root/gate/"
# the README's anchors table, verbatim, as the table the Rust tests are held to
{
  echo '# Anchors (vendored)'
  echo
  echo 'Copied from `examples/dcfid_gate/README.md` in Exsecutor between its `anchors:begin` / `anchors:end`'
  echo 'markers (see PROVENANCE.md). `cargo test --lib` parses this table and asserts that src/gate.rs'
  echo 'gives these verdicts. Input spelling: `\xNN` a byte, `{c*N}` N copies of c, `\\` a backslash;'
  echo '`n` is `=` for the byte count, else the length handed to the gate.'
  echo
  sed -n '/<!-- anchors:begin -->/,/<!-- anchors:end -->/p' "$readme"
} > "$root/gate/ANCHORS.md"

sha() { sha256sum "$1" | cut -d' ' -f1; }
exsc_sha="$(sha "$exsc")"
{
  cat <<HEAD
# Provenance of gate/

The gate is written in Exsecutor (a Latin-keyword systems language) and
compiled to C by \`exsc aedifica --emitte c\`. The emitted C is vendored here so
that building DCF-ID needs only a C11 compiler: no \`fasmg\`, no \`exsc\`.
Nothing under \`gate/\` except \`glue.c\` and \`glue.h\` and this file was written
by hand; \`scripts/check-gate-fresh.sh\` re-emits and compares.

- Exsecutor commit that last touched the two sources:
  \`$(git -C "$ex" log -1 --format=%H -- examples/dcfid_gate examples/dcf_net_gate)\`
  (checkout HEAD when vendored: \`$(git -C "$ex" rev-parse HEAD)\`)
- Vendored on: $(date -u +%Y-%m-%d)
- Command line (the shared network gate FIRST, then this one; one C unit):

      exsc aedifica --hospes x86_64-linux --emitte c   examples/dcf_net_gate/dcf_net_gate.exsc examples/dcfid_gate/dcfid_gate.exsc -o gate/dcfid_gate.gen.c
      exsc aedifica --hospes x86_64-linux --emitte h   (same sources)                                                            -o gate/dcfid_gate.gen.h
      exsc aedifica --hospes x86_64-linux --emitte rs  (same sources)                                                            -o gate/dcfid_gate.gen.rs

- sha256 of the compiler binary used (\`build/exsc\`): \`$exsc_sha\`
  (this file's digests below are what is machine-checked; the compiler digest is
  recorded, not re-derivable without rebuilding Exsecutor at that commit)

## Digests (checked by scripts/check-gate-fresh.sh)

Sources, in the Exsecutor checkout (checked when one is available):

\`\`\`
$(sha "$net")  exsecutor:examples/dcf_net_gate/dcf_net_gate.exsc
$(sha "$unit")  exsecutor:examples/dcfid_gate/dcfid_gate.exsc
$(sha "$readme")  exsecutor:examples/dcfid_gate/README.md
$(sha "$ex/examples/abortus/tutela.c")  exsecutor:examples/abortus/tutela.c
$(sha "$ex/examples/abortus/tutela.h")  exsecutor:examples/abortus/tutela.h
\`\`\`

Vendored files, in this repository (always checked):

\`\`\`
$(cd "$root" && for f in gate/dcfid_gate.gen.c gate/dcfid_gate.gen.h gate/dcfid_gate.gen.rs gate/tutela.c gate/tutela.h gate/ANCHORS.md gate/glue.c gate/glue.h; do echo "$(sha "$f")  $f"; done)
\`\`\`

\`glue.c\` and \`glue.h\` are listed so that an edit to them shows up in review;
they are hand-written, not emitted.

## What each file is

| file | what |
|---|---|
| \`dcfid_gate.gen.c\` | the emitted C unit: \`dcf_net_gate\` (IPv4, port, interval) and \`dcfid_gate\` (username, session id / token, cents, Stripe-Signature shape) |
| \`dcfid_gate.gen.h\` | its generated C face |
| \`dcfid_gate.gen.rs\` | its generated Rust face (kept for reference and for the freshness check; src/gate.rs calls the glue, not these externs) |
| \`tutela.c\`, \`tutela.h\` | Exsecutor's \`examples/abortus\` guard, byte-identical: makes a trap return to a setjmp guard instead of ending the process |
| \`glue.c\`, \`glue.h\` | hand-written: one thunk per gate function, each run under a tutela guard |
| \`ANCHORS.md\` | the gate README's anchors table; \`cargo test --lib\` holds src/gate.rs to it |

## Trap policy and thread-safety

The gates are total (the Exsecutor-side corpus includes a no-trap sweep), so a
trap should be unreachable. If one happens anyway, \`exsrt_abortus\` returns to
the guard opened in \`glue.c\` and the Rust wrapper treats the call as a refusal
(fail closed, logged at error level). Without a guard \`tutela.c\` prints and
\`abort()\`s; every call in this crate is guarded.

Is the guard thread-safe? Read from \`tutela.c\`: the guard chain (\`summa\`) and
the depth counter (\`profunditas\`) are \`static _Thread_local\`, and \`exsrt_abortus\`
long-jumps only to a guard on its own thread's chain. The service is
multi-threaded (tokio) and calls the gate from async handlers, but never holds
a guard across an \`.await\`: the whole call is one synchronous FFI call, so a
guard is opened and closed on one thread, and between it and a trap there are
only C frames (tutela.h precondition P1). \`cargo test --lib\` exercises the trap
path from 8 threads at once (\`gate::tests::trap_returns_to_the_guard_on_every_thread\`).
That is a test of the mechanism with an injected trap, not a proof; the
soundness argument is in \`examples/abortus/README.md\` in Exsecutor.

## Licence

**Pending owner decision.** The \`.exsc\` sources are GPL-3.0-or-later.
Exsecutor's LICENSE.EXCEPTION (Exception A) frees only the compiler's own
contribution to emitted C, not the author's logic expressed in the source, and
this repository's README says BSD-3-Clause while Cargo.toml says
\`Proprietary\`. Shipping the emitted \`dcfid_gate.gen.c\` and \`tutela.c\` here
needs a relicensing grant of the kind LICENSE.GRANTS GRANT 1 gives for custos
-- not made, and not this change's to make. Until then this directory is
vendored for evaluation.
HEAD
} > "$root/gate/PROVENANCE.md"
echo "vendor-gate: gate/ regenerated from $ex"
