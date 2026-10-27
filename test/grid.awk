# Reads a `langc ir` dump and prints one `NAME [ARGS...]` line for each case of
# the differential grid. A Flag parameter takes 0 and 1. A Nat parameter takes
# small values, and, when the entry has no loop, also the values at the 2^32
# and 2^64 limits (ADD_CARRY and MUL_CARRY cases). An entry with a loop gets
# only small values, because a large count runs past the evaluator fuel.
BEGIN {
  small = "0 1 2 3 5 7"
  big = small " 4294967295 4294967296 4294967297 18446744073709551615"
  n = 0
}
/^func / {
  n++
  name[n] = $2
  sig = $0
  sub(/^func [^ ]+ \(/, "", sig)
  sub(/\).*$/, "", sig)
  gsub(/,/, "", sig)
  types[n] = sig
  loop[n] = 0
  next
}
/^ +(repeat|while) / { loop[n] = 1 }
END {
  for (i = 1; i <= n; i++) cases(name[i], types[i], loop[i] ? small : big)
}
function cases(nm, ty, nats,    t, nt, k, c, nc, j, v, nv, m, out) {
  nc = 1
  c[1] = nm
  nt = split(ty, t, " ")
  for (k = 1; k <= nt; k++) {
    nv = split(t[k] == "flag" ? "0 1" : nats, v, " ")
    m = 0
    for (j = 1; j <= nc; j++) {
      for (i2 = 1; i2 <= nv; i2++) out[++m] = c[j] " " v[i2]
    }
    nc = m
    for (j = 1; j <= nc; j++) c[j] = out[j]
  }
  for (j = 1; j <= nc; j++) print c[j]
}
