//! crypto.rs — the cryptographic core of svault.
//!
//! TEACHING NOTE: every function here COMPOSES an audited primitive. We never
//! implement a cipher, hash, or KDF ourselves — that is rule #1 of applied
//! cryptography ("don't roll your own crypto"). Our job is to wire vetted
//! building blocks together *correctly*, because the dangerous mistakes live in
//! the wiring (nonce reuse, weak KDF params, missing authentication), not in the
//! primitives themselves.
//!
//! The pipeline (matches 1Password's Two-Secret Key Derivation, 2SKD):
//!
//!   master password ──NFKD/trim──> Argon2id(salt) ─┐
//!   Secret Key (128-bit) ──HKDF(salt=vault_id)──────┴─XOR─> Master Key
//!   Master Key ──HKDF-expand──> KEK ──AES-256-GCM──> wraps random Vault Key
//!   Vault Key ──AES-256-GCM(fresh nonce/entry)──> encrypts each secret
//!
//! Why XOR the two derived keys? Because if EITHER input is unknown to the
//! attacker, the output is unknown. A server thief who steals the vault file
//! still lacks the 128-bit Secret Key, so brute-forcing the (possibly weak)
//! master password is useless — they'd also have to guess 128 random bits.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

// ---- sizes (in bytes) ----
pub const KEY_LEN: usize = 32; // 256-bit keys everywhere
pub const NONCE_LEN: usize = 12; // AES-GCM standard nonce = 96 bits
pub const SALT_LEN: usize = 16; // Argon2 salt (>= 8 required); 128 bits is plenty
pub const SECRET_KEY_LEN: usize = 16; // the 1Password-style Secret Key = 128 bits
pub const VAULT_ID_LEN: usize = 16; // random per-vault id, used as HKDF salt

// ---- Argon2id parameters ----
// OWASP 2026 floor is m=19MiB,t=2,p=1. For an offline vault (we can afford to be
// slow) we go higher: 64 MiB of memory, 3 passes, 1 lane. Memory-hardness is what
// breaks GPU/ASIC cracking farms — each guess must rent 64 MiB, not just CPU.
const ARGON2_M_COST_KIB: u32 = 64 * 1024; // 64 MiB
const ARGON2_T_COST: u32 = 3; // iterations (passes)
const ARGON2_P_COST: u32 = 1; // parallelism (lanes)

// HKDF "info" labels — domain separation so keys derived for different purposes
// can never collide even if they share input material.
const INFO_SECRET_KEY: &[u8] = b"svault/secret-key/v1";
const INFO_KEK: &[u8] = b"svault/kek/v1";

/// Authenticated-encryption output: a fresh random nonce plus ciphertext+tag.
/// The nonce is NOT secret (it's stored in clear) — it only needs to be UNIQUE
/// per (key, message). The 16-byte GCM auth tag is appended inside `ct`.
pub struct Sealed {
    pub nonce: [u8; NONCE_LEN],
    pub ct: Vec<u8>,
}

/// Fill an N-byte array from the OS CSPRNG. Used for salts, vault ids, the
/// Secret Key, the Vault Key, and nonces. `OsRng` pulls from the kernel
/// (getentropy/getrandom) — never use a non-cryptographic RNG for any of these.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Stretch the master password with Argon2id into a 32-byte key.
/// This is the "make each guess expensive" step. A human password has maybe
/// ~40 bits of entropy; Argon2id makes each verification cost ~64MiB + real
/// time, so billions of guesses become economically impossible.
fn argon2id_derive(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(KEY_LEN),
    )
    .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|e| anyhow!("argon2 derive: {e}"))?;
    Ok(out)
}

/// Expand the high-entropy Secret Key into a 32-byte key via HKDF-SHA256.
/// The Secret Key is already random (128 bits), so we don't need Argon2 here —
/// HKDF just shapes it to the right length and domain-separates it. We salt with
/// the vault id (analogous to 1Password salting with the account id).
fn secret_key_expand(secret_key: &[u8], vault_id: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(vault_id), secret_key);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    // expand() only fails if the output length is absurd (>255*32 bytes); 32 is fine.
    hk.expand(INFO_SECRET_KEY, out.as_mut())
        .expect("hkdf expand len");
    out
}

/// THE 2SKD STEP. Combine the password-derived key and the Secret-Key-derived
/// key by XOR to form the Master Key. XOR is perfect here: the result reveals
/// nothing unless you know BOTH inputs.
///
/// We normalize the password to Unicode NFKD before hashing (like 1Password), so
/// a character typed in two byte-equivalent ways (e.g. "é" as one code point vs.
/// "e" + combining accent) still unlocks the same vault. Whitespace is trimmed.
pub fn derive_master_key(
    password: &str,
    secret_key: &[u8; SECRET_KEY_LEN],
    salt: &[u8; SALT_LEN],
    vault_id: &[u8; VAULT_ID_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    use unicode_normalization::UnicodeNormalization;
    let normalized: Zeroizing<String> = Zeroizing::new(password.trim().nfkd().collect());
    let p_key = argon2id_derive(normalized.as_bytes(), salt)?; // expensive, password-based
    let s_key = secret_key_expand(secret_key, vault_id); // cheap, entropy-based

    let mut master = Zeroizing::new([0u8; KEY_LEN]);
    for i in 0..KEY_LEN {
        master[i] = p_key[i] ^ s_key[i];
    }
    Ok(master)
}

/// Derive the Key-Encrypting-Key (KEK) from the Master Key via HKDF-expand.
/// WHY a separate KEK instead of using the Master Key directly? Key hierarchy:
/// the KEK only ever wraps (encrypts) the random Vault Key. To change the master
/// password we re-derive the KEK and re-wrap ONE key — we never touch the
/// thousands of encrypted entries. (See `rotate-master`.)
pub fn derive_kek(master: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, master); // master is already high-entropy
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(INFO_KEK, kek.as_mut()).expect("hkdf expand len");
    kek
}

/// AEAD encrypt with AES-256-GCM. Returns a fresh random nonce + ciphertext+tag.
///
/// CRITICAL INVARIANT: a (key, nonce) pair must NEVER repeat. With GCM, nonce
/// reuse under the same key is catastrophic (it can leak the authentication key
/// and XOR of plaintexts). We generate a fresh 96-bit random nonce on EVERY
/// call. 96 random bits is safe for the modest number of writes a vault does.
///
/// `aad` (additional authenticated data) is authenticated but not encrypted —
/// we bind a version/context string so ciphertext can't be replayed in a
/// different context without the tag failing.
pub fn aead_seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes = random_bytes::<NONCE_LEN>();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(Sealed {
        nonce: nonce_bytes,
        ct,
    })
}

/// AEAD decrypt. Returns an error if the tag fails — which happens if the key is
/// wrong (wrong master password OR wrong Secret Key) OR the ciphertext was
/// tampered with. This is the property that makes tampering loud, not silent:
/// you get an Err, never silently-corrupted plaintext.
pub fn aead_open(key: &[u8; KEY_LEN], sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&sealed.nonce);
    // Wrap the recovered plaintext in `Zeroizing` so the decrypted bytes (which
    // may be a key, e.g. the unwrapped Vault Key) are wiped from the heap on drop
    // instead of lingering in freed memory.
    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &sealed.ct,
                aad,
            },
        )
        .map_err(|_| {
            anyhow!("decryption failed: wrong password/Secret Key, or vault was tampered with")
        })?;
    Ok(Zeroizing::new(pt))
}

// =============================== tests ===============================
#[cfg(test)]
mod tests {
    use super::*;

    const AAD: &[u8] = b"svault/test";

    #[test]
    fn aead_round_trip() {
        let key = random_bytes::<KEY_LEN>();
        let msg = b"hunter2 is a terrible password";
        let sealed = aead_seal(&key, msg, AAD).unwrap();
        let out = aead_open(&key, &sealed, AAD).unwrap();
        assert_eq!(out.as_slice(), msg);
    }

    #[test]
    fn tampering_is_detected() {
        let key = random_bytes::<KEY_LEN>();
        let mut sealed = aead_seal(&key, b"top secret", AAD).unwrap();
        sealed.ct[0] ^= 0x01; // flip a single bit
        assert!(aead_open(&key, &sealed, AAD).is_err(), "tamper must fail");
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = random_bytes::<KEY_LEN>();
        let k2 = random_bytes::<KEY_LEN>();
        let sealed = aead_seal(&k1, b"data", AAD).unwrap();
        assert!(aead_open(&k2, &sealed, AAD).is_err());
    }

    #[test]
    fn nonce_is_unique_per_call() {
        // Not proof of CSPRNG quality, but catches a hard-coded/constant nonce bug.
        let key = random_bytes::<KEY_LEN>();
        let a = aead_seal(&key, b"x", AAD).unwrap();
        let b = aead_seal(&key, b"x", AAD).unwrap();
        assert_ne!(a.nonce, b.nonce, "nonces must differ across encryptions");
    }

    #[test]
    fn wrong_secret_key_changes_master() {
        let salt = random_bytes::<SALT_LEN>();
        let vid = random_bytes::<VAULT_ID_LEN>();
        let sk1 = random_bytes::<SECRET_KEY_LEN>();
        let mut sk2 = sk1;
        sk2[0] ^= 0x01; // differ by one bit
        let m1 = derive_master_key("same-password", &sk1, &salt, &vid).unwrap();
        let m2 = derive_master_key("same-password", &sk2, &salt, &vid).unwrap();
        assert_ne!(
            *m1, *m2,
            "different Secret Key must yield different master key"
        );
    }

    #[test]
    fn nfkd_equivalent_passwords_match() {
        let salt = random_bytes::<SALT_LEN>();
        let vid = random_bytes::<VAULT_ID_LEN>();
        let sk = random_bytes::<SECRET_KEY_LEN>();
        // "café" with é as one code point (U+00E9) vs e + combining accent (U+0301).
        let precomposed = "caf\u{00E9}";
        let decomposed = "cafe\u{0301}";
        assert_ne!(
            precomposed.as_bytes(),
            decomposed.as_bytes(),
            "inputs differ in bytes"
        );
        let m1 = derive_master_key(precomposed, &sk, &salt, &vid).unwrap();
        let m2 = derive_master_key(decomposed, &sk, &salt, &vid).unwrap();
        assert_eq!(
            *m1, *m2,
            "NFKD-equivalent passwords must derive the same key"
        );
    }

    #[test]
    fn wrong_password_changes_master() {
        let salt = random_bytes::<SALT_LEN>();
        let vid = random_bytes::<VAULT_ID_LEN>();
        let sk = random_bytes::<SECRET_KEY_LEN>();
        let m1 = derive_master_key("password-a", &sk, &salt, &vid).unwrap();
        let m2 = derive_master_key("password-b", &sk, &salt, &vid).unwrap();
        assert_ne!(*m1, *m2);
    }
}
