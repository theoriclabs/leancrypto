import LeanCrypto.Native
import LeanCrypto.Encoding

/-! Password hashing with scrypt and a self-describing encoding:
`$scrypt$ln=<logN>,r=<r>,p=<p>$<base64url salt>$<base64url hash>`. -/
namespace LeanCrypto.Password

structure Params where
  logN : Nat := 15
  r : Nat := 8
  p : Nat := 1
  saltLen : Nat := 16
  keyLen : Nat := 32
  deriving Repr, BEq

structure Decoded where
  logN : Nat
  r : Nat
  p : Nat
  salt : ByteArray
  hash : ByteArray

private def parseKV (key : String) (s : String) : Option Nat := do
  let pre := key ++ "="
  if !s.startsWith pre then none
  let v := (s.drop pre.length).toString
  if v.isEmpty || (v.length > 1 && v.startsWith "0") then none
  v.toNat?

/-- Parse an encoded hash; `none` if malformed. -/
def decode (encoded : String) : Option Decoded := do
  match encoded.splitOn "$" with
  | ["", "scrypt", ps, saltS, hashS] =>
    match ps.splitOn "," with
    | [a, b, c] =>
      let logN ← parseKV "ln" a
      let r ← parseKV "r" b
      let p ← parseKV "p" c
      let salt ← Base64Url.decode saltS
      let hash ← Base64Url.decode hashS
      if hash.size == 0 then none
      return { logN, r, p, salt, hash }
    | _ => none
  | _ => none

def encode (logN r p : Nat) (salt hash : ByteArray) : String :=
  s!"$scrypt$ln={logN},r={r},p={p}${Base64Url.encode salt}${Base64Url.encode hash}"

/-- Hash a password with a fresh random salt. -/
def hash (password : String) (params : Params := {}) : IO String := do
  let salt ← randomBytes params.saltLen
  match scrypt password.toUTF8 salt params.logN params.r params.p params.keyLen with
  | .ok h => return encode params.logN params.r params.p salt h
  | .error e => throw <| IO.userError e

/-- Verify a password against an encoded hash in constant time. Returns `false`
for malformed input or parameters scrypt rejects. -/
def verify (password : String) (encoded : String) : Bool :=
  match decode encoded with
  | none => false
  | some d =>
    match scrypt password.toUTF8 d.salt d.logN d.r d.p d.hash.size with
    | .ok h => constantTimeEq h d.hash
    | .error _ => false

/-- True if `encoded` is malformed or was produced with parameters other than
`params`, so the caller should rehash after a successful verify. -/
def needsRehash (encoded : String) (params : Params := {}) : Bool :=
  match decode encoded with
  | none => true
  | some d => d.logN != params.logN || d.r != params.r || d.p != params.p
      || d.salt.size != params.saltLen || d.hash.size != params.keyLen

end LeanCrypto.Password
