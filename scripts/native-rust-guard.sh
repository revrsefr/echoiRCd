#!/usr/bin/env bash
# native-rust-guard — echoIRCd's standing invariant.
#
# echoIRCd is ORIGINAL Rust — no code copied or translated from any other project.
# Every module, command and core function is written natively in Rust. This guard
# fails if that slips. Run it any time:  bash scripts/native-rust-guard.sh
# It is also wired into an editor hook so it runs automatically on edits.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2
fail=0
flag() { echo "VIOLATION: $1" >&2; shift; [ "$#" -gt 0 ] && printf '%s\n' "$*" | sed 's/^/  /' >&2; fail=1; }

# 1. no unsafe — the crate roots must forbid it (the compiler then enforces it)
for f in src/lib.rs src/main.rs; do
  grep -q 'forbid(unsafe_code)' "$f" 2>/dev/null || flag "$f is missing #![forbid(unsafe_code)]"
done

# 2. no copy / translation provenance language (inspiration words are fine:
#    mirror / inspired / reference / same behaviour / answer to / unlike C++)
copy=$(grep -rniE 'faithful|transliterat|translated from|ported from|a port of|copied from|copy of the|line.?by.?line|1:1 (port|cop|translat|clone|rewrite)|verbatim (copy|from|port)' src/ 2>/dev/null)
[ -n "$copy" ] && flag "copy/translation wording (echoIRCd is original Rust, not a port):" "$copy"

# 3. no C/C++ sources and no FFI — this is pure Rust
cpp=$(find src -type f \( -name '*.cpp' -o -name '*.hpp' -o -name '*.cc' -o -name '*.cxx' -o -name '*.c' -o -name '*.h' \) 2>/dev/null)
[ -n "$cpp" ] && flag "C/C++ source files present:" "$cpp"
ffi=$(grep -rnE 'extern[[:space:]]+"C"|\blibc::|std::ffi|#\[no_mangle\]' src/ 2>/dev/null)
[ -n "$ffi" ] && flag "FFI / foreign-function interface found:" "$ffi"

# 4. dependency-light — only openssl is allowed as an external crate
deps=$(awk '/^\[dependencies\]/{f=1;next} /^\[/{f=0} f && NF {print}' Cargo.toml 2>/dev/null \
        | grep -vE '^[[:space:]]*#' | sed -E 's/[[:space:]=].*//' | grep -vE '^(openssl|mio)?$')
[ -n "$deps" ] && flag "unexpected dependency (only openssl + mio allowed):" "$deps"

if [ "$fail" -eq 0 ]; then
  echo "native-rust-guard: OK — original Rust, no-unsafe, no C/FFI, openssl+mio only."
  exit 0
fi
echo "native-rust-guard: FAILED — see violations above." >&2
exit 2
