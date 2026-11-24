# Changelog

User-visible changes are recorded here. Versions use semantic versioning and
are published as `vX.Y.Z` Git tags.

## [Unreleased]

## [0.2.0] - 2026-11-24

- Add OpenSSL-backed AES-256-GCM authenticated encryption with 32-byte keys,
  caller-supplied 12-byte nonces, associated data, and 16-byte tags.

## [0.1.1] - 2026-11-24

- Upgrade the Lean toolchain to 4.36.0.

## [0.1.0] - 2026-09-22

### Added

- `sha256`, `hmacSha256`, `constantTimeEq`, `randomBytes` and `scrypt` over
  OpenSSL 3 libcrypto.
- Strict pure-Lean `Base64`, `Base64Url` (unpadded) and `Hex` encoders and
  decoders.
- `Password.hash`, `verify` and `needsRehash` with the self-describing
  `$scrypt$ln=,r=,p=$salt$hash` format.
- libcrypto is merged into the package's `extern_lib`, so downstream
  executables link with no extra configuration.
- Decision record 0001 (Q10: crypto provider).
