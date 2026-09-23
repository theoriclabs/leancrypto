import LeanCrypto
open LeanCrypto

def hx (s : String) : ByteArray := (Hex.decode s).get!
def str (s : String) : ByteArray := s.toUTF8
def rep (b : UInt8) (n : Nat) : ByteArray := ⟨Array.replicate n b⟩

structure St where
  pass : Nat := 0
  fail : Nat := 0

abbrev T := StateT St IO

def check (name : String) (ok : Bool) : T Unit := do
  if ok then modify fun s => { s with pass := s.pass + 1 }
  else
    IO.eprintln s!"FAIL: {name}"
    modify fun s => { s with fail := s.fail + 1 }

def eqHex (name : String) (got : ByteArray) (want : String) : T Unit := do
  let g := Hex.encode got
  if g != want then IO.eprintln s!"  got  {g}\n  want {want}"
  check name (g == want)

def sha256Tests : T Unit := do
  eqHex "sha256 empty" (sha256 .empty) "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  eqHex "sha256 abc" (sha256 (str "abc")) "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  eqHex "sha256 448-bit" (sha256 (str "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

def hmacTests : T Unit := do
  eqHex "rfc4231 tc1" (hmacSha256 (rep 0x0b 20) (str "Hi There"))
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
  eqHex "rfc4231 tc2" (hmacSha256 (str "Jefe") (str "what do ya want for nothing?"))
    "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
  eqHex "rfc4231 tc3" (hmacSha256 (rep 0xaa 20) (rep 0xdd 50))
    "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
  eqHex "rfc4231 tc4" (hmacSha256 (hx "0102030405060708090a0b0c0d0e0f10111213141516171819") (rep 0xcd 50))
    "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
  eqHex "rfc4231 tc5 (truncated)" ((hmacSha256 (rep 0x0c 20) (str "Test With Truncation")).extract 0 16)
    "a3b6167473100ee06e0c796c2955552b"
  eqHex "rfc4231 tc6" (hmacSha256 (rep 0xaa 131) (str "Test Using Larger Than Block-Size Key - Hash Key First"))
    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
  eqHex "rfc4231 tc7" (hmacSha256 (rep 0xaa 131)
      (str "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."))
    "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
  eqHex "hmac empty key" (hmacSha256 .empty .empty)
    "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"

def scryptCase (name : String) (pw salt : String) (logN r p : Nat) (want : String) : T Unit :=
  match scrypt (str pw) (str salt) logN r p 64 with
  | .ok h => eqHex name h want
  | .error e => do IO.eprintln e; check name false

def scryptTests : T Unit := do
  scryptCase "rfc7914 N=16" "" "" 4 1 1
    "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
  scryptCase "rfc7914 N=1024" "password" "NaCl" 10 8 16
    "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
  scryptCase "rfc7914 N=16384" "pleaseletmein" "SodiumChloride" 14 8 1
    "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"
  check "scrypt rejects logN=0" (match scrypt .empty .empty 0 1 1 32 with | .error _ => true | .ok _ => false)
  check "scrypt rejects huge memory" (match scrypt .empty .empty 30 8 1 32 with | .error _ => true | .ok _ => false)
  check "scrypt rejects dkLen=0" (match scrypt .empty .empty 4 1 1 0 with | .error _ => true | .ok _ => false)

def base64Tests : T Unit := do
  let vs := [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="),
             ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")]
  for (p, e) in vs do
    check s!"base64 encode {p}" (Base64.encode (str p) == e)
    check s!"base64 decode {e}" ((Base64.decode e).map (·.data) == some (str p).data)
  for bad in ["Zg", "Zg=", "Z===", "Zh==", "Zm9=", "Zg==Zg==", "Zm9v\n", "Zm-v", "Zm=v", "===="] do
    check s!"base64 rejects {bad}" (Base64.decode bad).isNone
  check "base64 binary" (Base64.encode (hx "fbff") == "+/8=")
  for (p, e) in vs do
    let u := e.replace "=" ""
    check s!"base64url encode {p}" (Base64Url.encode (str p) == u)
    check s!"base64url decode {u}" ((Base64Url.decode u).map (·.data) == some (str p).data)
  check "base64url binary" (Base64Url.encode (hx "fbff") == "-_8")
  for bad in ["Zg==", "Zm8=", "Z", "Zm9vY", "Zh", "Zm9", "+/8", "Zm 9", "Zg.", "é"] do
    check s!"base64url rejects {bad}" (Base64Url.decode bad).isNone
  -- round trips over all lengths 0..70 with varied bytes
  for n in [0:70] do
    let b : ByteArray := ⟨(Array.range n).map fun i => (i * 37 + n).toUInt8⟩
    check s!"base64url roundtrip {n}" ((Base64Url.decode (Base64Url.encode b)).map (·.data) == some b.data)
    check s!"base64 roundtrip {n}" ((Base64.decode (Base64.encode b)).map (·.data) == some b.data)
    check s!"hex roundtrip {n}" ((Hex.decode (Hex.encode b)).map (·.data) == some b.data)

def hexTests : T Unit := do
  check "hex encode" (Hex.encode (hx "00ff10ab") == "00ff10ab")
  check "hex upper decode" ((Hex.decode "DEADbeef").map (·.data) == some #[0xde, 0xad, 0xbe, 0xef])
  check "hex empty" ((Hex.decode "").map (·.size) == some 0)
  for bad in ["a", "0g", "abc", " 0a", "0x"] do
    check s!"hex rejects {bad}" (Hex.decode bad).isNone

def ctTests : T Unit := do
  check "ct eq same" (constantTimeEq (str "abc") (str "abc"))
  check "ct eq diff" (!constantTimeEq (str "abc") (str "abd"))
  check "ct eq len" (!constantTimeEq (str "abc") (str "abcd"))
  check "ct eq empty" (constantTimeEq .empty .empty)
  check "ct eq empty vs 1" (!constantTimeEq .empty (str "a"))

def randTests : T Unit := do
  let a ← randomBytes 32
  let b ← randomBytes 32
  check "random length" (a.size == 32 && b.size == 32)
  check "random distinct" (a.data != b.data)
  check "random zero" ((← randomBytes 0).size == 0)
  check "random large" ((← randomBytes 100000).size == 100000)

def passwordTests : T Unit := do
  let fast : Password.Params := { logN := 10 }
  let h ← Password.hash "correct horse" fast
  check "pw format" (h.startsWith "$scrypt$ln=10,r=8,p=1$")
  check "pw verify ok" (Password.verify "correct horse" h)
  check "pw verify wrong" (!Password.verify "correct horsf" h)
  check "pw verify empty" (!Password.verify "" h)
  let h2 ← Password.hash "correct horse" fast
  check "pw salted" (h != h2)
  check "pw needsRehash same" (!Password.needsRehash h fast)
  check "pw needsRehash default" (Password.needsRehash h)
  check "pw needsRehash r" (Password.needsRehash h { fast with r := 16 })
  check "pw needsRehash malformed" (Password.needsRehash "garbage")
  let hd ← Password.hash "pässwörd"
  check "pw default params" (hd.startsWith "$scrypt$ln=15,r=8,p=1$" && !Password.needsRehash hd)
  check "pw unicode verify" (Password.verify "pässwörd" hd)
  for bad in ["", "garbage", "$scrypt$", "$scrypt$ln=10,r=8,p=1$abc", "$argon2id$ln=10,r=8,p=1$AAAA$AAAA",
              "$scrypt$ln=10,r=8$AAAA$AAAA", "$scrypt$ln=010,r=8,p=1$AAAA$AAAA",
              "$scrypt$ln=0,r=8,p=1$AAAA$AAAA", "$scrypt$ln=40,r=8,p=1$AAAA$AAAA",
              "$scrypt$ln=10,r=8,p=1$AA=A$AAAA", "$scrypt$ln=10,r=8,p=1$AAAA$", h ++ "$x",
              h.replace "p=1" "p=2"] do
    check s!"pw malformed {bad}" (!Password.verify "correct horse" bad)

def main : IO UInt32 := do
  let (_, st) ← (do sha256Tests; hmacTests; scryptTests; base64Tests; hexTests; ctTests; randTests; passwordTests).run {}
  IO.println s!"{st.pass} passed, {st.fail} failed"
  return if st.fail == 0 then 0 else 1
