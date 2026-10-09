#!/usr/bin/env bash
# scripts/check-gate-fresh.sh -- is gate/ what gate/PROVENANCE.md says it is?
#
#   1. always: every digest in the "Vendored files" block still matches.
#   2. when an Exsecutor checkout with build/exsc is available ($EXSC, or
#      $EXSECUTOR/build/exsc): re-emit the C unit, C face and Rust face from
#      the two sources and cmp them against gate/, cmp tutela.c/h, and check
#      the source digests. Otherwise print [skip] for this part.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
prov="$root/gate/PROVENANCE.md"
fail=0

[ -f "$prov" ] || { echo "[FAIL] gate/PROVENANCE.md missing"; exit 1; }
if (cd "$root" && grep -E '^[0-9a-f]{64}  gate/' "$prov" | sha256sum -c --quiet - 2>/dev/null); then
  echo "[ok]   vendored files match the digests in gate/PROVENANCE.md"
else
  echo "[FAIL] a vendored file differs from the digest in gate/PROVENANCE.md:"
  (cd "$root" && grep -E '^[0-9a-f]{64}  gate/' "$prov" | sha256sum -c 2>&1 | grep -v ': OK$' || true)
  fail=1
fi

exsc="${EXSC:-}"
ex="${EXSECUTOR:-}"
if [ -z "$exsc" ] && [ -n "$ex" ]; then exsc="$ex/build/exsc"; fi
if [ -z "$ex" ] && [ -n "$exsc" ]; then ex="$(cd "$(dirname "$exsc")/.." && pwd)"; fi
if [ -z "$exsc" ] || [ ! -x "$exsc" ] || [ ! -f "$ex/examples/dcfid_gate/dcfid_gate.exsc" ]; then
  echo "[skip] re-emission: no Exsecutor checkout with build/exsc (set EXSECUTOR or EXSC)"
  [ "$fail" -eq 0 ] && exit 0 || exit 1
fi

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
net="$ex/examples/dcf_net_gate/dcf_net_gate.exsc"
unit="$ex/examples/dcfid_gate/dcfid_gate.exsc"
for k in c h rs; do
  "$exsc" aedifica --hospes x86_64-linux --emitte "$k" "$net" "$unit" -o "$work/g.$k" >/dev/null 2>&1 || true
  if [ -s "$work/g.$k" ] && cmp -s "$work/g.$k" "$root/gate/dcfid_gate.gen.$k"; then
    echo "[ok]   --emitte $k re-emitted, byte-identical to gate/dcfid_gate.gen.$k"
  else
    echo "[FAIL] --emitte $k differs from gate/dcfid_gate.gen.$k (or exsc failed)"; fail=1
  fi
done
for f in tutela.c tutela.h; do
  cmp -s "$ex/examples/abortus/$f" "$root/gate/$f" && echo "[ok]   gate/$f is byte-identical to examples/abortus/$f" \
    || { echo "[FAIL] gate/$f differs from examples/abortus/$f"; fail=1; }
done
want="$(sed -n '/<!-- anchors:begin -->/,/<!-- anchors:end -->/p' "$ex/examples/dcfid_gate/README.md")"
have="$(sed -n '/<!-- anchors:begin -->/,/<!-- anchors:end -->/p' "$root/gate/ANCHORS.md")"
[ "$want" = "$have" ] && echo "[ok]   gate/ANCHORS.md carries the README's anchors table verbatim" \
  || { echo "[FAIL] gate/ANCHORS.md differs from the README's anchors table"; fail=1; }
grep -E '^[0-9a-f]{64}  exsecutor:' "$prov" | while read -r sum name; do
  p="$ex/${name#exsecutor:}"
  if [ "$(sha256sum "$p" | cut -d' ' -f1)" = "$sum" ]; then echo "[ok]   source ${name#exsecutor:} matches its recorded digest"
  else echo "[FAIL] source ${name#exsecutor:} changed since it was vendored"; exit 1; fi
done || fail=1
[ "$fail" -eq 0 ] && echo "gate: fresh" || { echo "gate: STALE"; exit 1; }
