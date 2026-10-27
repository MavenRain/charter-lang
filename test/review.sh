#!/bin/sh
# Regression checks for the staged compiler review.
set -eu
tmp=$(mktemp -d "${TMPDIR:-/tmp}/lang-review.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

cat >"$tmp/capture.lang" <<'EOF'
keep : ℕ → ℕ → ℕ
keep x y = x

value : Unit → ℕ → ℕ → ℕ
value u y = keep y
EOF
normal=$(build/langc eval "$tmp/capture.lang" value)
printf 'value : Unit → ℕ → ℕ → ℕ\nvalue = %s\n\nanswer : ℕ\nanswer = value unit 4 9\n' "$normal" >"$tmp/roundtrip.lang"
test "$(build/langc eval "$tmp/roundtrip.lang" answer)" = 4

# Reducing a closure can expose a constructor with the binder's old name.
cat >"$tmp/constructor.lang" <<'EOF'
constant : Unit → DecE
constant u = decRelease

value : Unit → DecE
value decRelease = constant decRelease
EOF
normal=$(build/langc eval "$tmp/constructor.lang" value)
printf 'value : Unit → DecE\nvalue = %s\n\nanswer : ℕ\nanswer = fold 1 2 3 (value unit)\n' "$normal" >"$tmp/roundtrip.lang"
test "$(build/langc eval "$tmp/roundtrip.lang" answer)" = 1

# A generated eta binder must also print as a source identifier.
printf 'value : Unit → ℕ → ℕ → ℕ\nvalue u = natAdd\n' >"$tmp/eta.lang"
normal=$(build/langc eval "$tmp/eta.lang" value)
printf 'value : Unit → ℕ → ℕ → ℕ\nvalue = %s\n\nanswer : ℕ\nanswer = value unit 4 9\n' "$normal" >"$tmp/roundtrip.lang"
test "$(build/langc eval "$tmp/roundtrip.lang" answer)" = 13

# More than 64 live binders used to read past the printer's name table.
awk 'BEGIN {
  printf "value : "; for (i = 0; i < 70; i++) printf "Unit → ";
  printf "Unit\nvalue"; for (i = 0; i < 70; i++) printf " u%d", i;
  print " = u69"
}' >"$tmp/binders.lang"
awk 'BEGIN {
  for (i = 0; i < 70; i++) printf "fun u%d => ", i;
  print "u69"
}' >"$tmp/want"
build/langc eval "$tmp/binders.lang" value >"$tmp/got"
cmp "$tmp/want" "$tmp/got"

# bind preserves a Sum error and can change the success type.
cat >"$tmp/sum.lang" <<'EOF'
input : Sum ℕ ℕ
input = inl 7

output : Sum ℕ Bool
output = bind input (λ x → inr true)

right : Sum ℕ ℕ
right = inr 7

mapped : Sum ℕ Bool
mapped = bind right (λ x → inr true)
EOF
test "$(build/langc eval "$tmp/sum.lang" output)" = 'inl 7'
test "$(build/langc eval "$tmp/sum.lang" mapped)" = 'inr true'
# A truncated normal form must not be reported as successful evaluation.
printf 'value : Stack\nvalue = fold (λ (s : Stack) → push 0 s) bottom 10000\n' >"$tmp/large.lang"
status=0
build/langc eval "$tmp/large.lang" value >"$tmp/got" 2>"$tmp/err" || status=$?
test "$status" = 1
test ! -s "$tmp/got"
case "$(cat "$tmp/err")" in
  'langc: EVAL_PRINT:'*) ;;
  *) exit 1 ;;
esac
echo 'review regressions: passed'
