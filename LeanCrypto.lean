import LeanCrypto.Native
import LeanCrypto.Encoding
import LeanCrypto.Password

namespace LeanCrypto

structure SealedBox where
  nonce : ByteArray
  ciphertext : ByteArray
  tag : ByteArray
  deriving BEq

/-- AES-256-GCM via OpenSSL. The caller must ensure nonce uniqueness per key. -/
def aes256GcmSeal (key nonce plaintext aad : ByteArray) : Except String SealedBox :=
  if key.size == 32 && nonce.size == 12 then
    (aes256GcmSealRaw key nonce plaintext aad).map fun (ciphertext, tag) =>
      { nonce, ciphertext, tag }
  else
    .error "AEAD requires a 32-byte key and a 12-byte nonce"

/-- AES-256-GCM authenticated decryption via OpenSSL. -/
def aes256GcmOpen (key nonce ciphertext tag aad : ByteArray) : Except String ByteArray :=
  if key.size == 32 && nonce.size == 12 && tag.size == 16 then
    aes256GcmOpenRaw key nonce ciphertext tag aad
  else
    .error "AEAD requires a 32-byte key, a 12-byte nonce, and a 16-byte tag"

abbrev leanCryptoAes256GcmSeal := aes256GcmSeal
abbrev leanCryptoAes256GcmOpen := aes256GcmOpen

end LeanCrypto
