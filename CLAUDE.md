# CLAUDE.md — svault

Project-specific instructions for Claude Code working in this repo.

## What this is
`svault` is a learning-grade, zero-knowledge, **dual-secret (2SKD-style)** password
vault CLI in Rust. It composes audited crypto primitives — it does NOT roll its own.
Read `README.md` for the architecture and the honest "not-for-real-passwords-yet"
disclaimer.

## Toolchain
- Rust (stable), built with `cargo`.
- **`cargo` may not be on PATH.** If a command fails with `command not found: cargo`,
  prefix with `source ~/.cargo/env &&`.

## The QA gate (non-negotiable)
Every change must pass the gate before it is considered done. The gate is defined
once in the `Makefile` and mirrored in `.github/workflows/ci.yml`:

```
make qa     # = fmt-check + clippy -D warnings + test + build + audit
```

Equivalently:
```
source ~/.cargo/env
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
cargo audit                    # needs: cargo install cargo-audit --locked
```

Rules:
- **Zero warnings.** clippy runs with `-D warnings`; warnings fail the build.
- **Format is enforced.** Run `cargo fmt` before committing; CI runs `cargo fmt --check`.
- **Tests must stay green** (currently 23 tests). Add tests for new behavior.
- **No known-vulnerable deps.** `cargo audit` checks `Cargo.lock` against the RustSec
  advisory DB. Note: advisories are published upstream, so a previously-green audit can go
  red with no code change — when that happens, bump the flagged dep or document the
  accepted risk; don't disable the check.

## Crypto hard rules (do not violate)
- Never invent or hand-roll a cipher, hash, KDF, or MAC. Only compose vetted crates.
- Fresh random nonce (`OsRng`) on **every** AEAD encrypt — never reuse a (key, nonce).
- AEAD only (AES-256-GCM); the tag is verified on every decrypt. No unauthenticated modes.
- All secret-bearing buffers use `Zeroizing` (wipe-on-drop): passwords, derived keys,
  Vault Key, decrypted plaintext, TOTP seeds.
- Comment every crypto decision inline — the code is meant to teach.

## Security / repo hygiene
- This repo is **PUBLIC**. Never commit a real vault or a Secret Key.
- `.gitignore` keeps out `vault.json`, `*.vault`, `.svault/`, `/target`. Keep it that way.
- Atomic writes only for the vault file (temp + fsync + rename), mode `0600` on unix.

## Code map
| File          | Responsibility                                                       |
|---------------|----------------------------------------------------------------------|
| `src/main.rs` | clap CLI parsing → command dispatch; best-effort `mlockall`.         |
| `src/crypto.rs`| 2SKD derivation, HKDF/KEK, AES-256-GCM seal/open. The teaching core.|
| `src/vault.rs`| on-disk serde model, atomic load/save, put/get/list/remove/rotate.  |
| `src/cli.rs`  | rpassword prompts; Secret Key format/parse.                          |
| `src/passgen.rs`| CSPRNG password generator.                                         |
| `src/totp.rs` | RFC 6238 TOTP (2FA) code computation.                                |
| `src/clip.rs` | clipboard copy + auto-clear.                                         |

## Definition of done
A task is done when: code compiles, `make qa` is green, behavior is covered by a test,
and (if user-facing) `README.md` is updated. End work with **Done + Next**.
