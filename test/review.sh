#!/bin/sh
# Regression checks for the staged compiler review.
set -eu
tmp=$(mktemp -d "${TMPDIR:-/tmp}/lang-review.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

cat >"$tmp/capture.lang" <<'EOF'
def keep : Nat -> Nat -> Nat := fun x y => x
def value : Unit -> Nat -> Nat -> Nat := fun u y => keep y
EOF
normal=$(build/langc eval "$tmp/capture.lang" value)
printf 'def value : Unit -> Nat -> Nat -> Nat := %s\ndef answer : Nat := value unit 4 9\n' "$normal" >"$tmp/roundtrip.lang"
test "$(build/langc eval "$tmp/roundtrip.lang" answer)" = 4

# Reducing a closure can expose a constructor with the binder's old name.
cat >"$tmp/constructor.lang" <<'EOF'
def constant : Unit -> Color := fun u => red
def value : Unit -> Color := fun red => constant red
EOF
normal=$(build/langc eval "$tmp/constructor.lang" value)
printf 'def value : Unit -> Color := %s\ndef answer : Nat := fold 1 2 3 (value unit)\n' "$normal" >"$tmp/roundtrip.lang"
test "$(build/langc eval "$tmp/roundtrip.lang" answer)" = 1

# A generated eta binder must also print as a source identifier.
printf 'def value : Unit -> Nat -> Nat -> Nat := fun u => natAdd\n' >"$tmp/eta.lang"
normal=$(build/langc eval "$tmp/eta.lang" value)
printf 'def value : Unit -> Nat -> Nat -> Nat := %s\ndef answer : Nat := value unit 4 9\n' "$normal" >"$tmp/roundtrip.lang"
test "$(build/langc eval "$tmp/roundtrip.lang" answer)" = 13

# More than 64 live binders used to read past the printer's name table.
awk 'BEGIN {
  printf "def value : "; for (i = 0; i < 70; i++) printf "Unit -> ";
  printf "Unit := fun "; for (i = 0; i < 70; i++) printf "u%d ", i;
  print "=> u69"
}' >"$tmp/binders.lang"
awk 'BEGIN {
  for (i = 0; i < 70; i++) printf "fun u%d => ", i;
  print "u69"
}' >"$tmp/want"
build/langc eval "$tmp/binders.lang" value >"$tmp/got"
cmp "$tmp/want" "$tmp/got"

# bind preserves a Sum error and can change the success type.
cat >"$tmp/sum.lang" <<'EOF'
def input : Sum Nat Nat := inl 7
def output : Sum Nat Flag := bind input (fun x => inr flagYes)
def right : Sum Nat Nat := inr 7
def mapped : Sum Nat Flag := bind right (fun x => inr flagYes)
EOF
test "$(build/langc eval "$tmp/sum.lang" output)" = 'inl 7'
test "$(build/langc eval "$tmp/sum.lang" mapped)" = 'inr flagYes'
# A truncated normal form must not be reported as successful evaluation.
printf 'def value : List Nat := fold (fun xs => cons 0 xs) nil 10000\n' >"$tmp/large.lang"
status=0
build/langc eval "$tmp/large.lang" value >"$tmp/got" 2>"$tmp/err" || status=$?
test "$status" = 1
test ! -s "$tmp/got"
case "$(cat "$tmp/err")" in
  'langc: EVAL_PRINT:'*) ;;
  *) exit 1 ;;
esac
echo 'review regressions: passed'
