# leancrypto

**SHA-256, HMAC, constant-time compare, secure random, scrypt password hashing
and strict base64/hex for Lean 4, backed by OpenSSL 3 libcrypto.**

Secret-dependent operations call OpenSSL through a small C FFI. Encodings are
pure Lean. See [docs/decisions/0001-q10-crypto-provider.md](docs/decisions/0001-q10-crypto-provider.md).

## Install

Requires OpenSSL 3 with a static `libcrypto.a`:

- macOS: `brew install openssl@3` (found in `/opt/homebrew/opt/openssl@3` or `/usr/local/opt/openssl@3`)
- Debian/Ubuntu: `apt install libssl-dev` (found under `/usr`)
- Elsewhere: set `OPENSSL_DIR` to the prefix containing `include/` and `lib/`.

```lean
require leancrypto from git "https://github.com/theoriclabs/leancrypto" @ "v0.1.0"
```

Toolchain: `leanprover/lean4:v4.33.0`.

## Linking

Downstream packages need no extra configuration. The `extern_lib leancrypto`
target builds one static archive, `libleancrypto.a`, containing the binding
object plus every object extracted from OpenSSL's `libcrypto.a`. Lake links
extern libs of all dependencies into every executable, so libcrypto ends up
statically linked and the binary has no runtime OpenSSL dependency. Verified
with a throwaway package that only contains the `require` line and a
`lean_exe`.

## API

```lean
namespace LeanCrypto
def sha256 (data : ByteArray) : ByteArray
def hmacSha256 (key data : ByteArray) : ByteArray
def constantTimeEq (a b : ByteArray) : Bool          -- CRYPTO_memcmp; false on length mismatch
def randomBytes (n : Nat) : IO ByteArray              -- RAND_bytes; throws on failure
def scrypt (password salt : ByteArray) (logN r p dkLen : Nat) : Except String ByteArray

Base64Url.encode : ByteArray → String                 -- no padding
Base64Url.decode : String → Option ByteArray          -- strict
Base64.encode    : ByteArray → String                 -- standard alphabet, padded
Base64.decode    : String → Option ByteArray          -- strict
Hex.encode       : ByteArray → String                 -- lowercase
Hex.decode       : String → Option ByteArray          -- either case

namespace Password
structure Params where
  logN : Nat := 15; r : Nat := 8; p : Nat := 1; saltLen : Nat := 16; keyLen : Nat := 32
def hash (password : String) (params : Params := {}) : IO String
def verify (password : String) (encoded : String) : Bool
def needsRehash (encoded : String) (params : Params := {}) : Bool
```

Strict decoding rejects padding (base64url), misplaced or missing padding
(base64), whitespace, characters outside the alphabet, impossible lengths and
non-zero trailing bits, so every byte string has exactly one accepted encoding.

`scrypt` computes `N = 2^logN`, rejects `logN` outside 1..30, zero `r`/`p`,
`dkLen` outside 1..1 MiB, and parameters needing more than 1 GiB.

Password hashes look like
`$scrypt$ln=15,r=8,p=1$<base64url salt>$<base64url hash>`. `verify` returns
`false` for malformed strings. After a successful `verify`, call `needsRehash`
with your current params and store a fresh `hash` if it returns `true`.

```lean
let stored ← LeanCrypto.Password.hash "hunter2"
if LeanCrypto.Password.verify "hunter2" stored then ...
```

## Trust notes

- Constant-time behaviour relies entirely on OpenSSL (`CRYPTO_memcmp`,
  HMAC, scrypt). It is not proved in Lean.
- Lengths are public: `constantTimeEq` returns early on length mismatch.
- libcrypto is statically linked: rebuild to pick up OpenSSL security fixes.
- `randomBytes` uses OpenSSL's CSPRNG (`RAND_bytes`).

## Tests

```
lake build && lake exe leancrypto_tests
```

Covers NIST SHA-256 vectors, RFC 4231 HMAC cases 1 to 7, RFC 7914 scrypt
vectors (N=16, 1024, 16384), RFC 4648 base64 vectors, base64url/hex round trips
and rejections, constant-time equality, random bytes and password hashing.

## Follow-ups (not built)

- RS256 / ES256 signatures (and JWKS support in LeanAPI)
- argon2id password hashing (OpenSSL 3.2+)

## License

MIT, see [LICENSE](LICENSE).
