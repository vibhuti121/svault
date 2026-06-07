//! totp.rs — RFC 6238 Time-based One-Time Passwords (the 6-digit 2FA codes).
//!
//! TEACHING NOTE: TOTP = HOTP (RFC 4226) with the counter set to
//! floor(unix_time / period). HOTP = a truncation of HMAC(secret, counter).
//! The "secret" is the base32 string an app shows you when you scan a 2FA QR.
//! We store that secret as a normal vault entry and compute codes on demand —
//! so your 2FA seeds get the same zero-knowledge protection as your passwords.

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1; // RFC 6238 default algorithm is HMAC-SHA1

type HmacSha1 = Hmac<Sha1>;

pub const DEFAULT_PERIOD: u64 = 30;
pub const DEFAULT_DIGITS: u32 = 6;

/// Decode a user-supplied base32 TOTP seed: strip spaces, uppercase, drop any
/// '=' padding, then RFC 4648 base32 (no-pad) decode.
pub fn decode_secret(seed: &str) -> Result<Vec<u8>> {
    let cleaned: String = seed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    data_encoding::BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|e| anyhow!("invalid base32 TOTP seed: {e}"))
}

/// Compute the OTP for a given unix timestamp. Pure function → easy to test
/// against the RFC 6238 published vectors.
pub fn code_at(secret: &[u8], unix_time: u64, period: u64, digits: u32) -> Result<String> {
    if secret.is_empty() {
        return Err(anyhow!("empty TOTP secret"));
    }
    let counter = unix_time / period;
    let mut mac =
        HmacSha1::new_from_slice(secret).map_err(|e| anyhow!("hmac key: {e}"))?;
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 §5.3): low 4 bits of the last byte pick an
    // offset; read 4 bytes there, mask the high bit, mod 10^digits.
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32) << 16)
        | ((hash[offset + 2] as u32) << 8)
        | (hash[offset + 3] as u32);
    let otp = bin % 10u32.pow(digits);
    Ok(format!("{:0width$}", otp, width = digits as usize))
}

/// Seconds remaining in the current TOTP window (for the countdown display).
pub fn seconds_remaining(unix_time: u64, period: u64) -> u64 {
    period - (unix_time % period)
}

/// Current unix time in seconds.
pub fn now_unix() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow!("clock before epoch: {e}"))?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors use the ASCII secret "12345678901234567890"
    // ("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" in base32) with HMAC-SHA1.
    const SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn rfc6238_vectors_sha1() {
        let secret = decode_secret(SEED_B32).unwrap();
        assert_eq!(secret, b"12345678901234567890");
        // (unix_time, expected 8-digit code) from RFC 6238 Appendix B, SHA1 column.
        let cases = [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
        ];
        for (t, expected) in cases {
            assert_eq!(code_at(&secret, t, 30, 8).unwrap(), expected, "t={t}");
        }
    }

    #[test]
    fn base32_is_tolerant() {
        // lowercase + spaces + padding should still decode
        let s = decode_secret("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(s, b"12345678901234567890");
    }

    #[test]
    fn countdown_in_range() {
        let r = seconds_remaining(45, 30);
        assert!((1..=30).contains(&r));
        assert_eq!(seconds_remaining(60, 30), 30);
    }
}
