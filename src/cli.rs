//! cli.rs — human-facing helpers: Secret Key formatting/parsing and prompts.

use anyhow::{bail, Result};
use std::io::Write;
use zeroize::Zeroizing;

use crate::crypto::SECRET_KEY_LEN;

/// Render the 16-byte Secret Key as a human-friendly grouped string, e.g.
/// `SK1-A1B2-C3D4-E5F6-...`. The `SK1` prefix is a version tag so the format can
/// evolve later. This is what the user writes down / stores like an Emergency Kit.
pub fn format_secret_key(sk: &[u8; SECRET_KEY_LEN]) -> String {
    let hex: String = sk.iter().map(|b| format!("{:02X}", b)).collect();
    let groups: Vec<String> = hex
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    format!("SK1-{}", groups.join("-"))
}

/// Parse a Secret Key string back to 16 bytes. Tolerant of the `SK1-` prefix,
/// dashes, and whitespace; case-insensitive hex.
pub fn parse_secret_key(s: &str) -> Result<[u8; SECRET_KEY_LEN]> {
    let body = s.trim();
    // Strip the version prefix FIRST — note '1' in "SK1" is a hex digit and would
    // otherwise leak into the parse. Match the prefix case-insensitively so a
    // pasted "sk1-..." works too.
    let body = if body.len() >= 3 && body[..3].eq_ignore_ascii_case("sk1") {
        let rest = &body[3..];
        rest.strip_prefix('-').unwrap_or(rest)
    } else {
        body
    };
    let cleaned: String = body.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.len() != SECRET_KEY_LEN * 2 {
        bail!(
            "Secret Key must be {} hex characters (got {})",
            SECRET_KEY_LEN * 2,
            cleaned.len()
        );
    }
    let mut out = [0u8; SECRET_KEY_LEN];
    for i in 0..SECRET_KEY_LEN {
        out[i] = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow::anyhow!("bad hex in Secret Key: {e}"))?;
    }
    Ok(out)
}

/// Prompt for a password without echoing it to the terminal. Returned wrapped in
/// `Zeroizing` so it is wiped from memory on drop.
pub fn prompt_password(label: &str) -> Result<Zeroizing<String>> {
    let p = rpassword::prompt_password(label)?;
    Ok(Zeroizing::new(p))
}

/// Prompt for a password twice and require they match (used at init / rotate).
pub fn prompt_new_password(label: &str) -> Result<Zeroizing<String>> {
    let a = prompt_password(label)?;
    let b = prompt_password("Confirm: ")?;
    if *a != *b {
        bail!("passwords did not match");
    }
    if a.trim().is_empty() {
        bail!("empty password is not allowed");
    }
    Ok(a)
}

/// Prompt for the Secret Key (shown as you type — it's long and you're copying
/// it from your saved Emergency Kit; visible entry avoids silent typos).
pub fn prompt_secret_key() -> Result<[u8; SECRET_KEY_LEN]> {
    print!("Secret Key: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    parse_secret_key(&line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_round_trips() {
        let sk: [u8; SECRET_KEY_LEN] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let s = format_secret_key(&sk);
        assert!(s.starts_with("SK1-"));
        assert_eq!(parse_secret_key(&s).unwrap(), sk);
    }

    #[test]
    fn parse_is_tolerant() {
        let sk = [0xABu8; SECRET_KEY_LEN];
        let s = format_secret_key(&sk).to_lowercase(); // lowercase + prefix
        assert_eq!(parse_secret_key(&format!("  {s}  ")).unwrap(), sk);
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(parse_secret_key("SK1-AABB").is_err());
    }
}
