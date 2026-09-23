// OpenSSL 3 libcrypto bindings for LeanCrypto.
#include <lean/lean.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/sha.h>

static lean_obj_res mk_bytes(const unsigned char *p, size_t n) {
  lean_object *r = lean_alloc_sarray(1, n, n);
  if (n) memcpy(lean_sarray_cptr(r), p, n);
  return r;
}

LEAN_EXPORT lean_obj_res leancrypto_sha256(b_lean_obj_arg data) {
  unsigned char out[32];
  SHA256(lean_sarray_cptr(data), lean_sarray_size(data), out);
  return mk_bytes(out, 32);
}

LEAN_EXPORT lean_obj_res leancrypto_hmac_sha256(b_lean_obj_arg key, b_lean_obj_arg data) {
  unsigned char out[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  static const unsigned char empty = 0;
  const unsigned char *k = lean_sarray_size(key) ? lean_sarray_cptr(key) : &empty;
  if (!HMAC(EVP_sha256(), k, (int)lean_sarray_size(key),
            lean_sarray_cptr(data), lean_sarray_size(data), out, &len)) {
    lean_internal_panic("leancrypto: HMAC-SHA256 failed");
  }
  return mk_bytes(out, len);
}

LEAN_EXPORT uint8_t leancrypto_ct_eq(b_lean_obj_arg a, b_lean_obj_arg b) {
  size_t n = lean_sarray_size(a);
  if (n != lean_sarray_size(b)) return 0;
  if (n == 0) return 1;
  return CRYPTO_memcmp(lean_sarray_cptr(a), lean_sarray_cptr(b), n) == 0;
}

LEAN_EXPORT lean_obj_res leancrypto_random_bytes(b_lean_obj_arg n_obj, lean_obj_arg w) {
  if (!lean_is_scalar(n_obj) || lean_unbox(n_obj) > INT32_MAX)
    return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string("leancrypto: randomBytes size too large")));
  size_t n = lean_unbox(n_obj);
  lean_object *r = lean_alloc_sarray(1, n, n);
  if (n && RAND_bytes(lean_sarray_cptr(r), (int)n) != 1) {
    lean_dec(r);
    return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string("leancrypto: RAND_bytes failed")));
  }
  return lean_io_result_mk_ok(r);
}

// Returns Except String ByteArray. Parameters validated on the Lean side.
LEAN_EXPORT lean_obj_res leancrypto_scrypt(b_lean_obj_arg pw, b_lean_obj_arg salt,
    uint64_t N, uint64_t r, uint64_t p, uint64_t maxmem, size_t dklen) {
  lean_object *out = lean_alloc_sarray(1, dklen, dklen);
  static const char empty = 0;
  const char *pp = lean_sarray_size(pw) ? (const char *)lean_sarray_cptr(pw) : &empty;
  const unsigned char *sp = lean_sarray_size(salt) ? lean_sarray_cptr(salt) : (const unsigned char *)&empty;
  int ok = EVP_PBE_scrypt(pp, lean_sarray_size(pw), sp, lean_sarray_size(salt),
                          N, r, p, maxmem, lean_sarray_cptr(out), dklen);
  if (ok != 1) {
    lean_dec(out);
    ERR_clear_error();
    lean_object *e = lean_alloc_ctor(0, 1, 0);
    lean_ctor_set(e, 0, lean_mk_string("scrypt: OpenSSL EVP_PBE_scrypt failed (parameters rejected or out of memory)"));
    return e;
  }
  lean_object *res = lean_alloc_ctor(1, 1, 0);
  lean_ctor_set(res, 0, out);
  return res;
}
