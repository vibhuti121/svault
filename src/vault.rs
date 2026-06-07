//! vault.rs — the on-disk model and the unlocked in-memory vault.
//!
//! On disk we store ONLY: a version, a random vault id, the Argon2 salt, the
//! KEK-wrapped Vault Key, and the per-entry ciphertexts. There is NO key and NO
//! plaintext anywhere in the file. That is the whole point of "zero-knowledge":
//! someone who steals `vault.json` learns nothing without the master password
//! AND the Secret Key.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use zeroize::Zeroizing;

use crate::crypto::{
    self, Sealed, KEY_LEN, NONCE_LEN, SALT_LEN, SECRET_KEY_LEN, VAULT_ID_LEN,
};

const CURRENT_VERSION: u32 = 1;
// AAD binds ciphertext to its purpose so a blob can't be replayed elsewhere.
const AAD_VAULT_KEY: &[u8] = b"svault/vaultkey/v1";

/// A nonce + ciphertext encoded as base64 strings for clean JSON storage.
#[derive(Serialize, Deserialize, Clone)]
struct SealedB64 {
    nonce: String,
    ct: String,
}

impl SealedB64 {
    fn from_sealed(s: &Sealed) -> Self {
        SealedB64 {
            nonce: STANDARD.encode(s.nonce),
            ct: STANDARD.encode(&s.ct),
        }
    }
    fn to_sealed(&self) -> Result<Sealed> {
        let nonce = decode_arr::<NONCE_LEN>(&self.nonce).context("decode nonce")?;
        let ct = STANDARD.decode(&self.ct).context("decode ciphertext")?;
        Ok(Sealed { nonce, ct })
    }
}

/// The serialized vault file (`vault.json`).
#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    vault_id: String,           // base64(16 bytes) — also used as HKDF salt for the Secret Key
    salt: String,               // base64(16 bytes) — Argon2id salt (public, just needs to be unique)
    wrapped_vault_key: SealedB64, // the random Vault Key, encrypted under the KEK
    entries: BTreeMap<String, SealedB64>, // name -> encrypted secret
}

impl VaultFile {
    fn salt_bytes(&self) -> Result<[u8; SALT_LEN]> {
        decode_arr::<SALT_LEN>(&self.salt)
    }
    fn vault_id_bytes(&self) -> Result<[u8; VAULT_ID_LEN]> {
        decode_arr::<VAULT_ID_LEN>(&self.vault_id)
    }
}

/// An unlocked vault held in memory: the decrypted Vault Key (zeroized on drop)
/// plus the file structure we read it from.
pub struct UnlockedVault {
    vault_key: Zeroizing<[u8; KEY_LEN]>,
    file: VaultFile,
}

/// AAD for an individual entry — binds the ciphertext to its NAME, so an
/// attacker can't move the "gmail" blob to the "bank" slot without detection.
fn entry_aad(name: &str) -> Vec<u8> {
    let mut aad = b"svault/entry/v1:".to_vec();
    aad.extend_from_slice(name.as_bytes());
    aad
}

/// Create a brand-new vault. Generates the salt, vault id, the 128-bit Secret
/// Key, and a random 256-bit Vault Key; wraps the Vault Key under the KEK;
/// writes the file. Returns the raw Secret Key so the caller can show it to the
/// user ONCE (we never persist it — like 1Password's Emergency Kit).
pub fn init(path: &Path, password: &str) -> Result<[u8; SECRET_KEY_LEN]> {
    if path.exists() {
        bail!("vault already exists at {} — refusing to overwrite", path.display());
    }
    let salt = crypto::random_bytes::<SALT_LEN>();
    let vault_id = crypto::random_bytes::<VAULT_ID_LEN>();
    let secret_key = crypto::random_bytes::<SECRET_KEY_LEN>();
    let vault_key = Zeroizing::new(crypto::random_bytes::<KEY_LEN>());

    // Derive master -> KEK and wrap the Vault Key.
    let master = crypto::derive_master_key(password, &secret_key, &salt, &vault_id)?;
    let kek = crypto::derive_kek(&master);
    let wrapped = crypto::aead_seal(&kek, vault_key.as_ref(), AAD_VAULT_KEY)?;

    let file = VaultFile {
        version: CURRENT_VERSION,
        vault_id: STANDARD.encode(vault_id),
        salt: STANDARD.encode(salt),
        wrapped_vault_key: SealedB64::from_sealed(&wrapped),
        entries: BTreeMap::new(),
    };
    write_file(path, &file)?;
    Ok(secret_key)
}

/// Open and decrypt an existing vault: re-derive the KEK from (password, Secret
/// Key) and unwrap the Vault Key. A wrong password or Secret Key makes the AEAD
/// tag fail, so unlocking fails loudly rather than returning a garbage key.
pub fn unlock(
    path: &Path,
    password: &str,
    secret_key: &[u8; SECRET_KEY_LEN],
) -> Result<UnlockedVault> {
    let file = read_file(path)?;
    if file.version != CURRENT_VERSION {
        bail!("unsupported vault version {}", file.version);
    }
    let salt = file.salt_bytes()?;
    let vault_id = file.vault_id_bytes()?;

    let master = crypto::derive_master_key(password, secret_key, &salt, &vault_id)?;
    let kek = crypto::derive_kek(&master);

    let wrapped = file.wrapped_vault_key.to_sealed()?;
    let vk_bytes = crypto::aead_open(&kek, &wrapped, AAD_VAULT_KEY)
        .map_err(|_| anyhow!("could not unlock: wrong master password or Secret Key"))?;
    let mut vault_key = Zeroizing::new([0u8; KEY_LEN]);
    if vk_bytes.len() != KEY_LEN {
        bail!("corrupt vault: bad vault key length");
    }
    vault_key.copy_from_slice(&vk_bytes);

    Ok(UnlockedVault { vault_key, file })
}

impl UnlockedVault {
    /// Add or overwrite a secret. Encrypted under the Vault Key with a fresh
    /// nonce and name-bound AAD.
    pub fn put(&mut self, name: &str, secret: &str) -> Result<()> {
        let sealed = crypto::aead_seal(&self.vault_key, secret.as_bytes(), &entry_aad(name))?;
        self.file
            .entries
            .insert(name.to_string(), SealedB64::from_sealed(&sealed));
        Ok(())
    }

    /// Decrypt and return one secret. Wrapped in `Zeroizing` so the plaintext is
    /// wiped from memory when the caller drops it.
    pub fn get(&self, name: &str) -> Result<Zeroizing<String>> {
        let entry = self
            .file
            .entries
            .get(name)
            .ok_or_else(|| anyhow!("no entry named '{name}'"))?;
        let sealed = entry.to_sealed()?;
        let pt = crypto::aead_open(&self.vault_key, &sealed, &entry_aad(name))?;
        let s = String::from_utf8(pt).context("entry was not valid UTF-8")?;
        Ok(Zeroizing::new(s))
    }

    /// List entry names only — values stay encrypted.
    pub fn list(&self) -> Vec<String> {
        self.file.entries.keys().cloned().collect()
    }

    /// Remove a secret. Returns true if something was removed.
    pub fn remove(&mut self, name: &str) -> bool {
        self.file.entries.remove(name).is_some()
    }

    /// Persist changes back to disk.
    pub fn save(&self, path: &Path) -> Result<()> {
        write_file(path, &self.file)
    }
}

/// Re-wrap the Vault Key under a new master password WITHOUT re-encrypting any
/// entries — the payoff of the key hierarchy. The Vault Key (and therefore every
/// entry ciphertext) is unchanged; only its KEK wrapper changes. The Secret Key
/// is unchanged across a master-password rotation, so the caller passes the one
/// it already collected for this session.
pub fn rotate_master(
    unlocked: &mut UnlockedVault,
    secret_key: &[u8; SECRET_KEY_LEN],
    new_password: &str,
) -> Result<()> {
    let salt = unlocked.file.salt_bytes()?;
    let vault_id = unlocked.file.vault_id_bytes()?;
    let master = crypto::derive_master_key(new_password, secret_key, &salt, &vault_id)?;
    let kek = crypto::derive_kek(&master);
    let wrapped = crypto::aead_seal(&kek, unlocked.vault_key.as_ref(), AAD_VAULT_KEY)?;
    unlocked.file.wrapped_vault_key = SealedB64::from_sealed(&wrapped);
    Ok(())
}

// ---- file IO helpers ----

fn write_file(path: &Path, file: &VaultFile) -> Result<()> {
    let json = serde_json::to_string_pretty(file).context("serialize vault")?;
    std::fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn read_file(path: &Path) -> Result<VaultFile> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("read {} (run `svault init` first?)", path.display()))?;
    let file: VaultFile = serde_json::from_str(&data).context("parse vault json")?;
    Ok(file)
}

/// Decode a base64 string into a fixed-size byte array, erroring on bad length.
fn decode_arr<const N: usize>(s: &str) -> Result<[u8; N]> {
    let v = STANDARD.decode(s).context("base64 decode")?;
    if v.len() != N {
        bail!("expected {N} bytes, got {}", v.len());
    }
    let mut a = [0u8; N];
    a.copy_from_slice(&v);
    Ok(a)
}

// =============================== tests ===============================
#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        // Date/random are unavailable; use the test name + pid for uniqueness.
        p.push(format!("svault_test_{}_{}.json", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn full_lifecycle() {
        let path = tmp("lifecycle");
        let sk = init(&path, "correct horse battery staple").unwrap();

        let mut v = unlock(&path, "correct horse battery staple", &sk).unwrap();
        v.put("gmail", "hunter2").unwrap();
        v.put("bank", "s3cr3t").unwrap();
        v.save(&path).unwrap();

        let v2 = unlock(&path, "correct horse battery staple", &sk).unwrap();
        assert_eq!(*v2.get("gmail").unwrap(), "hunter2");
        assert_eq!(*v2.get("bank").unwrap(), "s3cr3t");
        let mut names = v2.list();
        names.sort();
        assert_eq!(names, vec!["bank".to_string(), "gmail".to_string()]);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_password_cannot_unlock() {
        let path = tmp("wrongpw");
        let sk = init(&path, "right-password").unwrap();
        assert!(unlock(&path, "WRONG-password", &sk).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_secret_key_cannot_unlock() {
        let path = tmp("wrongsk");
        let sk = init(&path, "pw").unwrap();
        let mut bad = sk;
        bad[0] ^= 0xFF;
        assert!(unlock(&path, "pw", &bad).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn tampered_entry_fails() {
        let path = tmp("tamper");
        let sk = init(&path, "pw").unwrap();
        let mut v = unlock(&path, "pw", &sk).unwrap();
        v.put("x", "value").unwrap();
        v.save(&path).unwrap();

        // Corrupt the stored ciphertext by hand.
        let mut raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let ct = raw["entries"]["x"]["ct"].as_str().unwrap().to_string();
        let mut bytes = STANDARD.decode(&ct).unwrap();
        bytes[0] ^= 0x01;
        raw["entries"]["x"]["ct"] = serde_json::Value::String(STANDARD.encode(bytes));
        std::fs::write(&path, serde_json::to_string(&raw).unwrap()).unwrap();

        let v2 = unlock(&path, "pw", &sk).unwrap();
        assert!(v2.get("x").is_err(), "tampered entry must fail to decrypt");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn demo_show_ondisk_format() {
        // Run with: cargo test demo_show_ondisk_format -- --nocapture
        let path = tmp("demo_format");
        let sk = init(&path, "demo-master-password").unwrap();
        let mut v = unlock(&path, "demo-master-password", &sk).unwrap();
        v.put("gmail", "hunter2-the-password").unwrap();
        v.save(&path).unwrap();

        println!("\n=== Secret Key (shown once at init) ===");
        println!("{}", crate::cli::format_secret_key(&sk));
        println!("\n=== vault.json on disk — note: NO keys, NO plaintext ===");
        println!("{}", std::fs::read_to_string(&path).unwrap());
        let v2 = unlock(&path, "demo-master-password", &sk).unwrap();
        println!("=== decrypted 'gmail' after reopening = {:?} ===", *v2.get("gmail").unwrap());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rotate_master_preserves_entries() {
        let path = tmp("rotate");
        let sk = init(&path, "old-pw").unwrap();
        let mut v = unlock(&path, "old-pw", &sk).unwrap();
        v.put("x", "keepme").unwrap();
        rotate_master(&mut v, &sk, "new-pw").unwrap();
        v.save(&path).unwrap();

        assert!(unlock(&path, "old-pw", &sk).is_err(), "old pw must stop working");
        let v2 = unlock(&path, "new-pw", &sk).unwrap();
        assert_eq!(*v2.get("x").unwrap(), "keepme");
        std::fs::remove_file(&path).ok();
    }
}
