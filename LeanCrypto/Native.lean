namespace LeanCrypto

/-- SHA-256 digest (32 bytes), computed by OpenSSL. -/
@[extern "leancrypto_sha256"]
opaque sha256 (data : @& ByteArray) : ByteArray

/-- HMAC-SHA256 (32 bytes), computed by OpenSSL. -/
@[extern "leancrypto_hmac_sha256"]
opaque hmacSha256 (key data : @& ByteArray) : ByteArray

/-- Constant-time equality via `CRYPTO_memcmp`. Returns `false` on length
mismatch; the length itself is not treated as secret. -/
@[extern "leancrypto_ct_eq"]
opaque constantTimeEq (a b : @& ByteArray) : Bool

/-- `n` cryptographically secure random bytes from `RAND_bytes`. Throws on failure. -/
@[extern "leancrypto_random_bytes"]
opaque randomBytes (n : @& Nat) : IO ByteArray

@[extern "leancrypto_scrypt"]
private opaque scryptRaw (password salt : @& ByteArray) (n r p maxmem : UInt64)
    (dkLen : USize) : Except String ByteArray

/-- Upper bound on scrypt memory: 1 GiB. -/
def scryptMaxMem : Nat := 1024 * 1024 * 1024

/-- scrypt (RFC 7914) via `EVP_PBE_scrypt`, with `N = 2^logN`. Memory is capped
at `scryptMaxMem`. -/
def scrypt (password salt : ByteArray) (logN r p dkLen : Nat) : Except String ByteArray :=
  if logN == 0 || logN > 30 then .error "scrypt: logN must be in 1..30"
  else if r == 0 || p == 0 then .error "scrypt: r and p must be positive"
  else if r * p ≥ 2 ^ 30 then .error "scrypt: r * p must be < 2^30"
  else if dkLen == 0 || dkLen > 1024 * 1024 then .error "scrypt: dkLen must be in 1..1048576"
  else if 128 * r * (2 ^ logN + p + 1) > scryptMaxMem then .error "scrypt: parameters exceed memory limit"
  else scryptRaw password salt (2 ^ logN).toUInt64 r.toUInt64 p.toUInt64
    (scryptMaxMem + 1024 * 1024).toUInt64 dkLen.toUSize

end LeanCrypto
