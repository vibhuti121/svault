# svault — a zero-knowledge, dual-secret password vault

A small CLI password vault built **to learn how 1Password / Bitwarden actually
protect your data**. It implements the real architecture — Argon2id key
stretching, AEAD encryption, a key hierarchy, and 1Password-style **Two-Secret
Key Derivation (2SKD)** — composed entirely from audited crypto crates.

> ⚠️ **Learning-grade.** This is a faithful, working implementation of the
> architecture, with a full test suite. It is **not** a substitute for a
> professionally audited password manager for your real passwords yet — see
> [Limitations](#limitations). Use it to understand the design, not to guard your
> bank login.

---

## The architecture

```
master password ──trim/NFKD──► Argon2id(salt, 64MiB, t=3) ─┐
Secret Key (128-bit) ──HKDF(salt = vault_id)───────────────┴─ XOR ─► Master Key
Master Key ──HKDF-expand──► KEK ──AES-256-GCM──► wraps a random 256-bit Vault Key
Vault Key ──AES-256-GCM (fresh nonce per entry)──► encrypts each secret
```

On disk (`vault.json`) we store **only**: a version, a random `vault_id`, the
Argon2 `salt`, the KEK-wrapped Vault Key, and per-entry ciphertexts. **No keys.
No plaintext.** Steal the file and you learn nothing.

### Why each piece exists

| Piece | Purpose | The trap it avoids |
|---|---|---|
| **Argon2id** (memory-hard KDF) | Make each password guess cost ~64 MiB + real time | Fast hashes (plain SHA-256) let GPUs try billions/sec |
| **Unique random salt** | Stops precomputed (rainbow-table) attacks | Reused/no salt = shared cracking work |
| **AES-256-GCM (AEAD)** | Confidentiality **+** integrity (tamper detection) | Unauthenticated modes return silent garbage when tampered |
| **Fresh random nonce / encrypt** | (key, nonce) must never repeat | GCM nonce reuse can leak the auth key — catastrophic |
| **Secret Key + XOR (2SKD)** | Adds 128 bits the server never sees | Weak master password alone is crackable after a breach |
| **Key hierarchy (KEK→Vault Key)** | Change master password by re-wrapping one key | Otherwise every entry must be re-encrypted |
| **`zeroize`** | Wipe keys/plaintext from RAM after use | Secrets lingering in memory → swap/crash-dump leaks |
| **`mlockall` (best-effort)** | Ask the OS not to swap our pages to disk | Keys written to swap survive on disk after exit |
| **NFKD normalization** | Equivalent Unicode passwords derive the same key | "café" typed two ways would otherwise fail to unlock |

### Threat model

| Attack | Defended? | How |
|---|---|---|
| Vault file / "server" stolen | ✅ | Zero-knowledge + 128-bit Secret Key |
| Weak master password + stolen file | ✅ (mostly) | Argon2id + Secret Key make brute force infeasible |
| Vault file tampered byte-by-byte | ✅ | AEAD auth tag → decryption fails loudly |
| Malware on your unlocked machine | ❌ | Out of scope — no password manager defends this |

---

## Usage

```bash
cargo build --release

# create a vault — prints your Secret Key ONCE (save it like an Emergency Kit)
./target/release/svault init

./target/release/svault add gmail        # prompts master pw + Secret Key + value
./target/release/svault add gmail --generate            # store a strong random pw
./target/release/svault add gmail --generate --length 24 --no-symbols
./target/release/svault get gmail        # prints the secret
./target/release/svault get gmail --copy # to clipboard, auto-clears after 15s
./target/release/svault list             # names only (values stay encrypted)
./target/release/svault remove gmail
./target/release/svault rotate-master    # new master pw, same Secret Key & entries

# extras
./target/release/svault generate --length 24            # print a strong pw (no vault)
./target/release/svault totp-add work                   # store a 2FA base32 seed
./target/release/svault totp work                       # print current 6-digit code

# custom vault location
./target/release/svault --file /path/to/vault.json init
```

Default vault path: `~/.svault/vault.json`.

### Daily-driver extras

| Feature | What it does | Caveat |
|---|---|---|
| **Password generator** | CSPRNG (`OsRng`), one char/class guaranteed, ambiguous look-alikes removed | — |
| **TOTP 2FA** | RFC 6238 codes; seeds stored encrypted under `totp/<name>` | seed gets the same zero-knowledge protection as a password |
| **Clipboard auto-clear** | `--copy` writes to clipboard, overwrites + clears after 15s | a clipboard-history manager may have already snapshotted it — OS limit |
| **`mlockall`** | best-effort: keeps secret pages out of swap | needs `RLIMIT_MEMLOCK`; silently skipped if denied |

To unlock you always need **both** the master password **and** the Secret Key.
Lose either and the vault is unrecoverable — by design.

---

## Code map

| File | What it teaches |
|---|---|
| `src/crypto.rs` | The crypto core: 2SKD derivation, KEK, AEAD seal/open. Every decision is commented. Start here. |
| `src/vault.rs` | On-disk model, key hierarchy in practice, add/get/list/remove, rotate-master. |
| `src/cli.rs` | Secret Key formatting/parsing, no-echo password prompts. |
| `src/totp.rs` | RFC 6238 TOTP (HMAC-SHA1, dynamic truncation), verified against the RFC vectors. |
| `src/passgen.rs` | CSPRNG password generator. |
| `src/clip.rs` | Clipboard copy + auto-clear. |
| `src/main.rs` | clap CLI wiring + best-effort `mlockall`. |

```bash
cargo test    # 23 tests: AEAD round-trip, tamper detection, wrong-pw/wrong-key,
              # nonce uniqueness, NFKD equivalence, full lifecycle, rotate-master,
              # RFC 6238 TOTP vectors, password-generator invariants
```

---

## Limitations

Honest list of what's **not** here (and what a production tool adds):

- **No cloud sync / multi-device / SRP server authentication.** Local only.
- **`mlockall` is best-effort, not a guarantee.** If the OS denies it (no
  `RLIMIT_MEMLOCK`) we carry on; and it can't protect a page the kernel already
  copied. `zeroize` still wipes secrets after use.
- **Entry *names* are stored in clear** (only values are encrypted) — so the file
  reveals *that* you have a `gmail` entry, not its value. 1Password encrypts
  metadata too; a future version could encrypt the whole entry map.
- **Auto-lock timeout is N/A** for a per-command CLI — each command unlocks,
  does one thing, and exits, so nothing stays unlocked in the background.
- **No protection against malware on an unlocked machine** (keyloggers, screen
  capture, clipboard-history snapshots) — out of scope for any vault.
- **No independent security audit.** Until that exists, treat this as a teaching
  artifact, not your daily driver.

## Sources

- [1Password Security Design White Paper](https://1passwordstatic.com/files/security/1password-white-paper.pdf) — §3 (Secret Key) & §8.2 (2SKD derivation)
- [Bitwarden — Encryption Key Derivation](https://bitwarden.com/help/kdf-algorithms/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
