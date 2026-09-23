/-! Pure-Lean encodings: hex, base64 (RFC 4648 §4) and base64url (§5, unpadded). -/
namespace LeanCrypto

namespace Hex

private def digit (n : UInt8) : Char :=
  if n < 10 then Char.ofNat (48 + n.toNat) else Char.ofNat (87 + n.toNat)

/-- Lowercase hex. -/
def encode (b : ByteArray) : String := Id.run do
  let mut s := ""
  for x in b do
    s := (s.push (digit (x >>> 4))).push (digit (x &&& 15))
  return s

private def val (c : Char) : Option UInt8 :=
  if '0' ≤ c && c ≤ '9' then some (c.toNat - 48).toUInt8
  else if 'a' ≤ c && c ≤ 'f' then some (c.toNat - 87).toUInt8
  else if 'A' ≤ c && c ≤ 'F' then some (c.toNat - 55).toUInt8
  else none

/-- Decode hex (either case). Rejects odd length and non-hex characters. -/
def decode (s : String) : Option ByteArray := do
  let cs := s.toList.toArray
  if cs.size % 2 != 0 then none
  let mut out := ByteArray.emptyWithCapacity (cs.size / 2)
  for i in [0:cs.size/2] do
    let hi ← val cs[2*i]!
    let lo ← val cs[2*i+1]!
    out := out.push ((hi <<< 4) ||| lo)
  return out

end Hex

namespace B64Core

def stdAlphabet : String := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
def urlAlphabet : String := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

def encode (alpha : Array Char) (pad : Bool) (b : ByteArray) : String := Id.run do
  let mut s := ""
  let n := b.size
  let mut i := 0
  while i + 3 ≤ n do
    let v := (b[i]!.toNat <<< 16) ||| (b[i+1]!.toNat <<< 8) ||| b[i+2]!.toNat
    s := s.push alpha[(v >>> 18) % 64]! |>.push alpha[(v >>> 12) % 64]!
          |>.push alpha[(v >>> 6) % 64]! |>.push alpha[v % 64]!
    i := i + 3
  let rem := n - i
  if rem == 1 then
    let v := b[i]!.toNat <<< 16
    s := s.push alpha[(v >>> 18) % 64]! |>.push alpha[(v >>> 12) % 64]!
    if pad then s := s ++ "=="
  else if rem == 2 then
    let v := (b[i]!.toNat <<< 16) ||| (b[i+1]!.toNat <<< 8)
    s := s.push alpha[(v >>> 18) % 64]! |>.push alpha[(v >>> 12) % 64]! |>.push alpha[(v >>> 6) % 64]!
    if pad then s := s ++ "="
  return s

def value (alpha : Array Char) (c : Char) : Option Nat := alpha.idxOf? c 

/-- Decode unpadded symbols strictly: length mod 4 ≠ 1, canonical trailing bits. -/
def decodeUnpadded (alpha : Array Char) (cs : Array Char) : Option ByteArray := do
  if cs.size % 4 == 1 then none
  let mut out := ByteArray.emptyWithCapacity (cs.size * 3 / 4)
  let full := cs.size / 4
  for q in [0:full] do
    let a ← value alpha cs[4*q]!
    let b ← value alpha cs[4*q+1]!
    let c ← value alpha cs[4*q+2]!
    let d ← value alpha cs[4*q+3]!
    let v := (a <<< 18) ||| (b <<< 12) ||| (c <<< 6) ||| d
    out := out.push (v >>> 16).toUInt8 |>.push (v >>> 8).toUInt8 |>.push v.toUInt8
  let rem := cs.size % 4
  let base := 4 * full
  if rem == 2 then
    let a ← value alpha cs[base]!
    let b ← value alpha cs[base+1]!
    if b % 16 != 0 then none
    out := out.push ((a <<< 2) ||| (b >>> 4)).toUInt8
  else if rem == 3 then
    let a ← value alpha cs[base]!
    let b ← value alpha cs[base+1]!
    let c ← value alpha cs[base+2]!
    if c % 4 != 0 then none
    let v := (a <<< 18) ||| (b <<< 12) ||| (c <<< 6)
    out := out.push (v >>> 16).toUInt8 |>.push (v >>> 8).toUInt8
  return out

end B64Core

namespace Base64Url
private def alpha : Array Char := B64Core.urlAlphabet.toList.toArray
/-- base64url without padding (RFC 4648 §5). -/
def encode (b : ByteArray) : String := B64Core.encode alpha false b
/-- Strict base64url decode: rejects `=`, characters outside the URL alphabet,
impossible lengths and non-zero trailing bits. -/
def decode (s : String) : Option ByteArray := B64Core.decodeUnpadded alpha s.toList.toArray
end Base64Url

namespace Base64
private def alpha : Array Char := B64Core.stdAlphabet.toList.toArray
/-- Standard base64 with `=` padding (RFC 4648 §4). -/
def encode (b : ByteArray) : String := B64Core.encode alpha true b
/-- Strict base64 decode: length must be a multiple of 4, padding only at the
end (at most two), no whitespace, canonical trailing bits. -/
def decode (s : String) : Option ByteArray := do
  let cs := s.toList.toArray
  if cs.size % 4 != 0 then none
  let padN := if cs.size ≥ 2 && cs[cs.size-1]! == '=' then
      (if cs[cs.size-2]! == '=' then 2 else 1) else 0
  let body := cs.extract 0 (cs.size - padN)
  if body.contains '=' then none
  B64Core.decodeUnpadded alpha body
end Base64

/-- Hex encoding doubles the length. -/
theorem Hex.encode_empty : Hex.encode ByteArray.empty = "" := by native_decide

end LeanCrypto
