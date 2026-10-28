#!/bin/sh
# The kit gate. `make check` runs it from the kit directory after the build.
set -eu
fail=0
count=0
for prog in examples/*.lang; do
  out=$(build/langc check "$prog" 2>&1) || true
  count=$((count + 1))
  if [ "$out" != "ok" ]; then
    echo "FAIL $prog: $out"
    fail=$((fail + 1))
  fi
done
echo "examples: $count checked, $fail failed"

tmp=${TMPDIR:-/tmp}/langc-gate.$$
mkdir -p "$tmp"
awk 'BEGIN { printf "deep : ℕ\ndeep = " } { } END {
  for (i = 0; i < 1100; i++) printf "("; printf "1"; for (i = 0; i < 1100; i++) printf ")"; print "" }' </dev/null >"$tmp/deep.lang"

# refusals DIR LABEL: each line of DIR/expect.txt is `FILE CODE`. `langc check`
# must exit 1 and print `langc: CODE: ...` on stderr.
refusals() {
  checked=0
  while read -r file code; do
    path="$1/$file"
    [ "$file" = "deep.lang" ] && path="$tmp/deep.lang"
    status=0
    build/langc check "$path" 2>"$tmp/err" >/dev/null || status=$?
    first=$(head -n 1 "$tmp/err")
    checked=$((checked + 1))
    case "$status:$first" in
      "1:langc: $code: "*) ;;
      *) echo "FAIL $file: want exit 1 and $code, got exit $status: $first"; fail=$((fail + 1)) ;;
    esac
  done <"$1/expect.txt"
  echo "$2 refusals: $checked checked"
}
refusals test/parse parse
refusals test/check check

# A refl refusal shows both normal forms.
build/langc check test/check/bad-refl.lang 2>"$tmp/err" >/dev/null || true
if ! rg -q -F 'the left side normalizes to 1201, the right side normalizes to 1200' "$tmp/err"; then
  echo "FAIL bad-refl.lang: the message does not show both normal forms"
  fail=$((fail + 1))
fi

# Each line of test/eval/expect.txt is `FILE NAME [ARGS] => OUTPUT`. `langc eval`
# must exit 0 and print OUTPUT. A trap also prints `langc: EVAL_OVERFLOW: NAME: ...`
# on stderr.
evals=0
while IFS= read -r line; do
  want=${line#* => }
  set -- ${line%% => *}
  file=$1
  name=$2
  shift 2
  status=0
  got=$(build/langc eval "examples/$file.lang" "$name" "$@" 2>"$tmp/err") || status=$?
  first=$(head -n 1 "$tmp/err")
  want_err=""
  [ "$want" = "trap" ] && want_err="langc: EVAL_OVERFLOW: $name: "
  evals=$((evals + 1))
  case "$status|$got|$first" in
    "0|$want|$want_err"*) ;;
    *) echo "FAIL eval $file $name: want $want, got exit $status: $got $first"; fail=$((fail + 1)) ;;
  esac
done <test/eval/expect.txt
echo "evals: $evals checked"

# eval_refused STATUS CODE NAME [ARGS]: `langc eval examples/entries.lang NAME
# ARGS` must exit STATUS and print `langc: CODE: NAME: ...` on stderr.
eval_refused() {
  want_status=$1
  code=$2
  shift 2
  status=0
  build/langc eval examples/entries.lang "$@" 2>"$tmp/err" >/dev/null || status=$?
  case "$status:$(head -n 1 "$tmp/err")" in
    "$want_status:langc: $code: $1: "*) ;;
    *) echo "FAIL eval $*: want exit $want_status and $code, got exit $status"; fail=$((fail + 1)) ;;
  esac
}
eval_refused 2 EVAL_ARGS addPrice 1
eval_refused 2 EVAL_ARGS addPrice x 1
eval_refused 2 EVAL_ARGS addPrice 18446744073709551616 1
eval_refused 2 EVAL_ARGS pick 2 4 9
eval_refused 1 EVAL_ENTRY nope

status=0
build/langc 2>/dev/null || status=$?
[ "$status" -eq 2 ] || { echo "FAIL usage: want exit 2, got $status"; fail=$((fail + 1)); }
status=0
build/langc check "$tmp/missing.lang" 2>/dev/null || status=$?
[ "$status" -eq 2 ] || { echo "FAIL missing file: want exit 2, got $status"; fail=$((fail + 1)); }

# The IR: each example lowers, with one func line for each entry.
irs=0
for f in examples/*.lang; do
  irs=$((irs + 1))
  status=0
  build/langc ir "$f" > "$tmp/ir.txt" 2> "$tmp/ir.err" || status=$?
  funcs=$(rg -c '^func ' "$tmp/ir.txt" || echo 0)
  entries=$(build/langc abi "$f" | rg -c '.' || echo 0)
  [ "$status" -eq 0 ] && [ "$funcs" -eq "$entries" ] || { echo "FAIL ir $f: exit $status, $funcs funcs for $entries entries: $(head -n 1 "$tmp/ir.err")"; fail=$((fail + 1)); }
done
echo "ir: $irs lowered"
status=0
build/langc check test/ir/closure.lang > /dev/null || status=$?
[ "$status" -eq 0 ] || { echo "FAIL closure.lang: check exit $status"; fail=$((fail + 1)); }
status=0
first=$(build/langc ir test/ir/closure.lang 2>&1 > /dev/null) || status=$?
case "$status:$first" in
  "1:langc: REFUSE_RUNTIME_CLOSURE: "*) ;;
  *) echo "FAIL closure.lang: want exit 1 and REFUSE_RUNTIME_CLOSURE, got exit $status: $first"; fail=$((fail + 1)) ;;
esac
got=$(build/langc eval test/ir/lazy.lang lazy 3 2>&1) || true
[ "$got" = "3" ] || { echo "FAIL lazy.lang: want 3, got $got"; fail=$((fail + 1)); }
build/langc ir test/ir/lazy.lang > /dev/null || { echo "FAIL lazy.lang: ir"; fail=$((fail + 1)); }
for want in "fmSum 3:15" "fmTrap 0:7" "fmTrap 2:5" "fmDemand 0:trap" "fmDemand 2:trap"; do
  call=${want%%:*}
  got=$(build/langc eval test/ir/spine.lang ${call% *} ${call#* } 2>"$tmp/err") || true
  want_err=""
  [ "${want#*:}" = "trap" ] && want_err="langc: EVAL_OVERFLOW: ${call% *}: "
  case "$got|$(head -n 1 "$tmp/err")" in
    "${want#*:}|$want_err"*) ;;
    *) echo "FAIL spine.lang $call: want ${want#*:}, got $got"; fail=$((fail + 1)) ;;
  esac
done
build/langc ir test/ir/spine.lang > /dev/null || { echo "FAIL spine.lang: ir"; fail=$((fail + 1)); }
for want in "fmTotal 1:6" "fmCount 4:6"; do
  call=${want%%:*}
  got=$(build/langc eval test/ir/freemon.lang ${call% *} ${call#* } 2>&1) || true
  [ "$got" = "${want#*:}" ] || { echo "FAIL freemon.lang $call: want ${want#*:}, got $got"; fail=$((fail + 1)); }
done
{ build/langc ir test/ir/freemon.lang > "$tmp/ir.txt" && rg -q "^func fmCount " "$tmp/ir.txt" && rg -q -F "add(l0, 1)" "$tmp/ir.txt"; } || { echo "FAIL freemon.lang: ir"; fail=$((fail + 1)); }
status=0
build/langc check test/ir/tree.lang > /dev/null || status=$?
[ "$status" -eq 0 ] || { echo "FAIL tree.lang: check exit $status"; fail=$((fail + 1)); }
status=0
first=$(build/langc ir test/ir/tree.lang 2>&1 > /dev/null) || status=$?
case "$status:$first" in
  "1:langc: REFUSE_RUNTIME_TREE: "*) ;;
  *) echo "FAIL tree.lang: want exit 1 and REFUSE_RUNTIME_TREE, got exit $status: $first"; fail=$((fail + 1)) ;;
esac
status=0
build/langc check test/ir/ind.lang > /dev/null || status=$?
[ "$status" -eq 0 ] || { echo "FAIL ind.lang: check exit $status"; fail=$((fail + 1)); }
for want in "double 3:6" "bump 2:6"; do
  call=${want%%:*}
  got=$(build/langc eval test/ir/ind.lang ${call% *} ${call#* } 2>&1) || true
  [ "$got" = "${want#*:}" ] || { echo "FAIL ind.lang $call: want ${want#*:}, got $got"; fail=$((fail + 1)); }
done
status=0
first=$(build/langc ir test/ir/ind.lang 2>&1 > /dev/null) || status=$?
case "$status:$first" in
  "1:langc: REFUSE_RUNTIME_TREE: "*) ;;
  *) echo "FAIL ind.lang: want exit 1 and REFUSE_RUNTIME_TREE, got exit $status: $first"; fail=$((fail + 1)) ;;
esac
status=0
build/langc check test/ir/optind.lang > /dev/null || status=$?
[ "$status" -eq 0 ] || { echo "FAIL optind.lang: check exit $status"; fail=$((fail + 1)); }
for want in "someGet 4:5" "noneGet 3:3" "pickGet 1:2" "pickGet 5:0"; do
  call=${want%%:*}
  got=$(build/langc eval test/ir/optind.lang ${call% *} ${call#* } 2>&1) || true
  [ "$got" = "${want#*:}" ] || { echo "FAIL optind.lang $call: want ${want#*:}, got $got"; fail=$((fail + 1)); }
done
status=0
first=$(build/langc ir test/ir/optind.lang 2>&1 > /dev/null) || status=$?
case "$status:$first" in
  "1:langc: REFUSE_RUNTIME_TREE: "*) ;;
  *) echo "FAIL optind.lang: want exit 1 and REFUSE_RUNTIME_TREE, got exit $status: $first"; fail=$((fail + 1)) ;;
esac

# The Wasm target: each module builds and is valid. Then the differential: on
# the grid of test/grid.awk, node and `langc eval` give the same result for
# each entry (trap == trap). The stderr of eval is not merged into stdout.
wasms=0
cases=0
mismatches=0
for f in examples/*.lang test/ir/spine.lang test/ir/lazy.lang test/ir/proof-trap.lang test/ir/nat-effects.lang; do
  w="$tmp/$(basename "$f" .lang).wasm"
  wasms=$((wasms + 1))
  if ! build/langc build "$f" -o "$w" 2>"$tmp/w.err" || ! wasm-validate "$w" 2>>"$tmp/w.err" ||
    ! wasm-objdump -x "$w" >/dev/null 2>>"$tmp/w.err"; then
    echo "FAIL wasm $f: $(head -n 1 "$tmp/w.err")"
    fail=$((fail + 1))
    continue
  fi
  build/langc ir "$f" | awk -f test/grid.awk >"$tmp/cases.txt"
  : >"$tmp/want.txt"
  while read -r call; do
    status=0
    want=$(build/langc eval "$f" $call 2>/dev/null) || status=$?
    [ "$status" -eq 0 ] || want="eval-exit-$status"
    echo "$want" >>"$tmp/want.txt"
  done <"$tmp/cases.txt"
  if ! node test/run-wasm.mjs "$w" - <"$tmp/cases.txt" >"$tmp/got.txt" 2>"$tmp/w.err"; then
    echo "FAIL node $f: $(head -n 1 "$tmp/w.err")"
    fail=$((fail + 1))
    continue
  fi
  cases=$((cases + $(rg -c '.' "$tmp/cases.txt" || echo 0)))
  paste -d '|' "$tmp/cases.txt" "$tmp/want.txt" "$tmp/got.txt" | awk -F '|' '$2 != $3' >"$tmp/bad.txt"
  bad=$(rg -c '.' "$tmp/bad.txt" || echo 0)
  mismatches=$((mismatches + bad))
  [ "$bad" -eq 0 ] || { echo "FAIL differential $f: $bad mismatches, first $(head -n 1 "$tmp/bad.txt")"; fail=$((fail + 1)); }
done
echo "wasm: $wasms modules valid"
echo "differential: $cases cases, $mismatches mismatches"
# A Bool argument larger than 1 traps (langc eval refuses it with EVAL_ARGS).
got=$(node test/run-wasm.mjs "$tmp/entries.wasm" pick 2 4 9 2>&1) || true
[ "$got" = "trap" ] || { echo "FAIL wasm pick 2 4 9: want trap, got $got"; fail=$((fail + 1)); }
# The canonical printer. Each committed .lang file that parses is canonical:
# `langc fmt F` equals F byte for byte, so fmt is idempotent on it. The
# fronttool AST dump of F equals the dump of `fmt F` (the round trip). Each
# test/fmt/X.lang formats to test/fmt/X.canon (X.canon is in the canonical
# list), the two dumps are equal, and `langc check` gives W_NONCANON on
# X.lang and no warning on X.canon.
same_dump() {
  build/fronttool dump "$1" >"$tmp/d1.txt" 2>&1 && build/fronttool dump "$2" >"$tmp/d2.txt" 2>&1 &&
    cmp -s "$tmp/d1.txt" "$tmp/d2.txt"
}
canon=0
for f in domain/domain.lang examples/*.lang test/check/*.lang test/ir/*.lang test/json/*.lang test/fmt/*.canon; do
  case "$f" in
    test/json/LEX_*.lang | test/json/PARSE_*.lang | test/json/W_NONCANON.lang) continue ;;
  esac
  canon=$((canon + 1))
  status=0
  build/langc fmt "$f" >"$tmp/fmt.out" 2>"$tmp/fmt.err" || status=$?
  if [ "$status" -ne 0 ] || ! cmp -s "$f" "$tmp/fmt.out"; then
    echo "FAIL fmt $f: not canonical, exit $status $(head -n 1 "$tmp/fmt.err")"
    fail=$((fail + 1))
  elif ! same_dump "$f" "$tmp/fmt.out"; then
    echo "FAIL round trip $f: the AST dump changes after fmt"
    fail=$((fail + 1))
  fi
done
pairs=0
for f in test/fmt/*.lang; do
  c="${f%.lang}.canon"
  pairs=$((pairs + 1))
  status=0
  build/langc fmt "$f" >"$tmp/fmt.out" 2>"$tmp/fmt.err" || status=$?
  if [ "$status" -ne 0 ] || ! cmp -s "$c" "$tmp/fmt.out"; then
    echo "FAIL fmt $f: the output is not $c, exit $status $(head -n 1 "$tmp/fmt.err")"
    fail=$((fail + 1))
  fi
  same_dump "$f" "$c" || { echo "FAIL round trip $f: the AST dump differs from $c"; fail=$((fail + 1)); }
  out=$(build/langc check "$f" 2>"$tmp/err") || true
  first=$(head -n 1 "$tmp/err")
  case "$out|$first" in
    "ok|langc: W_NONCANON: "*) ;;
    *) echo "FAIL check $f: want ok and W_NONCANON, got $out|$first"; fail=$((fail + 1)) ;;
  esac
  out=$(build/langc check "$c" 2>"$tmp/err") || true
  if [ "$out" != "ok" ] || [ -s "$tmp/err" ]; then
    echo "FAIL check $c: want ok and no warning, got $out|$(head -n 1 "$tmp/err")"
    fail=$((fail + 1))
  fi
done
echo "fmt: $canon canonical, $pairs non-canonical pairs"

# JSON shape: `langc check --json` on each test/json/*.lang gives the lines of
# test/json/expect.txt exactly (with the exit code and any stderr line).
jsons=0
for f in $(printf '%s\n' test/json/*.lang | LC_ALL=C sort); do
  jsons=$((jsons + 1))
  status=0
  build/langc check --json "$f" >"$tmp/j.out" 2>"$tmp/j.err" || status=$?
  echo "== $(basename "$f") exit $status"
  cat "$tmp/j.out"
  if [ -s "$tmp/j.err" ]; then echo "stderr: $(head -n 1 "$tmp/j.err")"; fi
done >"$tmp/json.txt"
if ! cmp -s test/json/expect.txt "$tmp/json.txt"; then
  echo "FAIL json: the output is not test/json/expect.txt: $(diff test/json/expect.txt "$tmp/json.txt" | rg '^[<>]' | head -n 2 | cut -c1-160 | tr '\n' ' ')"
  fail=$((fail + 1))
fi
# The progress line: typed "k of m" with k < m (a later declaration fails),
# an all-pass file, and laws "k of m" with k < m (a later law fails).
for want in 'progress-part:{"parsed":"3 of 3","typed":"2 of 3","laws":"0 of 0"}' \
  'progress-pass:{"parsed":"2 of 2","typed":"2 of 2","laws":"0 of 0"}' \
  'progress-laws:{"parsed":"3 of 3","typed":"2 of 3","laws":"1 of 2"}'; do
  got=$(build/langc check --json "test/json/${want%%:*}.lang" 2>/dev/null | tail -n 1) || true
  [ "$got" = "${want#*:}" ] || { echo "FAIL progress ${want%%:*}: want ${want#*:}, got $got"; fail=$((fail + 1)); }
done
# The laws count on examples/assets.lang (the natCMon laws) and on
# examples/kappa.lang (the kappa laws): not zero, and all of the laws
# type-check.
for f in assets kappa; do
  laws=$(build/langc check --json "examples/$f.lang" 2>/dev/null | tail -n 1 | rg -o -r '$1' '"laws":"([0-9]+ of [0-9]+)"') || true
  if [ -z "$laws" ] || [ "${laws% of *}" != "${laws#* of }" ] || [ "${laws% of *}" = 0 ]; then
    echo "FAIL progress $f: want laws \"m of m\" with m > 0, got $laws"
    fail=$((fail + 1))
  fi
done

# docs/DIAGNOSTICS.md has one row for each code in src/. Each code has
# test/json/CODE.lang (its first JSON line has that code), or its row gives
# "no fixture:" and a reason; not the two.
rg -o -I -N -r '$1$2$3' '"((?:LEX|PARSE|REFUSE|TYPE|NAME|EVAL|W)_[A-Z_]+)"|"(OOM|IO|IO_SIZE|USAGE|INTERNAL)"|langc: ((?:EVAL|REFUSE|TYPE)_[A-Z_]+):' src |
  LC_ALL=C sort -u >"$tmp/src-codes.txt"
rg -o -N -r '$1' '^\| `([A-Z_]+)` \|' docs/DIAGNOSTICS.md | LC_ALL=C sort -u >"$tmp/doc-codes.txt"
if ! cmp -s "$tmp/src-codes.txt" "$tmp/doc-codes.txt"; then
  echo "FAIL docs/DIAGNOSTICS.md: the code list is not the src/ list: $(diff "$tmp/src-codes.txt" "$tmp/doc-codes.txt" | rg '^[<>]' | tr '\n' ' ')"
  fail=$((fail + 1))
fi
codes=0
fixtures=0
reasons=0
while read -r code; do
  codes=$((codes + 1))
  row=$(rg "^\| \`$code\` \|" docs/DIAGNOSTICS.md) || row=""
  case "$row" in *"no fixture: "*) reason=1 ;; *) reason=0 ;; esac
  if [ -f "test/json/$code.lang" ] && [ "$reason" -eq 0 ]; then
    fixtures=$((fixtures + 1))
    first=$(build/langc check --json "test/json/$code.lang" 2>/dev/null | head -n 1) || true
    case "$first" in
      "{\"code\":\"$code\","*) ;;
      *) echo "FAIL test/json/$code.lang: the first JSON line is not code $code: $(echo "$first" | cut -c1-120)"; fail=$((fail + 1)) ;;
    esac
  elif [ ! -f "test/json/$code.lang" ] && [ "$reason" -eq 1 ]; then
    reasons=$((reasons + 1))
  else
    echo "FAIL $code: want test/json/$code.lang or a \"no fixture:\" reason in docs/DIAGNOSTICS.md, not the two"
    fail=$((fail + 1))
  fi
done <"$tmp/doc-codes.txt"
for f in $(printf '%s\n' test/json/*.lang | rg '^test/json/[A-Z_]+\.lang$'); do
  rg -q -x -F "$(basename "$f" .lang)" "$tmp/doc-codes.txt" || { echo "FAIL $f: the code is not in docs/DIAGNOSTICS.md"; fail=$((fail + 1)); }
done
echo "json: $jsons fixtures; diagnostics: $codes codes, $fixtures with a fixture, $reasons with no fixture"

rm -rf "$tmp"

if rg -n -g '!design/DESIGN.md' -g '!design/OFFCHAIN-ESCROWDAO.html' '\x{2013}|\x{2014}' . >/dev/null; then
  echo "FAIL: an em-dash or en-dash is in the kit"
  fail=$((fail + 1))
fi
echo "gate: $fail failures"
[ "$fail" -eq 0 ]
