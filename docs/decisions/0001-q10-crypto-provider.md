# 0001: Q10 crypto provider

Status: accepted (2026-09-22). Resolves DESIGN.md Q10 for LeanAPI M2.

## Context

LeanAPI needs SHA-256, HMAC-SHA256, constant-time comparison, secure random
bytes, base64url/hex, and a password hash with upgradeable parameters. The
choice was between a pure-Lean implementation and FFI to an established
library.

## Decision

- **Secret-dependent code goes through OpenSSL 3 libcrypto** (`SHA256`,
  `HMAC`, `CRYPTO_memcmp`, `RAND_bytes`, `EVP_PBE_scrypt`). Lean compiles to C
  through an optimizer and a boxed runtime we cannot audit for timing;
  OpenSSL's primitives are written and reviewed for constant-time behaviour
  and are the de-facto standard.
- **Pure Lean only for public-data encodings**: hex, base64, base64url. These
  never handle secrets whose timing matters (tokens are compared as decoded
  bytes via `constantTimeEq`), and pure Lean keeps them portable and provable.
- **Password hashing uses scrypt** (available in every OpenSSL 3) with a
  self-describing `$scrypt$ln=,r=,p=$salt$hash` encoding so parameters can be
  raised later (`Password.needsRehash`). Argon2id is a follow-up
  (OpenSSL 3.2+ only).

## Trust

- The trusted computing base includes OpenSSL libcrypto, the ~100-line C
  binding in `bindings/leancrypto.c`, and the Lean runtime.
- Constant-time guarantees are OpenSSL's, not proved in Lean. Lean code around
  the calls (e.g. `Password.decode`) branches only on public data (encoding
  format, lengths, parameters).
- `constantTimeEq` returns early on length mismatch: lengths are treated as
  public.

## Deployment

- OpenSSL 3 headers and a static `libcrypto.a` are required at build time:
  `brew install openssl@3` on macOS, `apt install libssl-dev` on Debian/Ubuntu,
  or `OPENSSL_DIR=<prefix>`.
- libcrypto is statically linked into every executable (see README "Linking"),
  so nothing is needed at run time. Security updates to OpenSSL therefore
  require a rebuild of the application.
