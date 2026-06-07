//! passgen.rs — cryptographically strong random password generator.
//!
//! TEACHING NOTE: the only thing that matters here is the source of randomness.
//! We use `OsRng` (the OS CSPRNG) and `gen_range`, which samples without modulo
//! bias. NEVER use a non-crypto RNG (e.g. a seeded `StdRng` with a guessable
//! seed) for a password — the whole point is unpredictability.

use rand::rngs::OsRng;
use rand::Rng;
use zeroize::Zeroizing;

// Character classes. Ambiguous look-alikes (0/O, 1/l/I) are omitted so generated
// passwords are easier to read/transcribe without weakening entropy meaningfully.
const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &[u8] = b"23456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";

/// Generate a random password of `len` characters. Includes symbols unless
/// `symbols` is false. Guarantees at least one char from each enabled class.
pub fn generate(len: usize, symbols: bool) -> Zeroizing<String> {
    let len = len.max(8); // refuse to make a trivially short password
    let mut classes: Vec<&[u8]> = vec![LOWER, UPPER, DIGITS];
    if symbols {
        classes.push(SYMBOLS);
    }
    let pool: Vec<u8> = classes.iter().flat_map(|c| c.iter().copied()).collect();

    let mut rng = OsRng;
    let mut out: Vec<u8> = Vec::with_capacity(len);

    // One guaranteed char from each class so the result always satisfies common
    // "must contain upper/lower/digit/symbol" policies.
    for class in &classes {
        out.push(class[rng.gen_range(0..class.len())]);
    }
    // Fill the rest from the combined pool.
    while out.len() < len {
        out.push(pool[rng.gen_range(0..pool.len())]);
    }
    // Shuffle so the guaranteed chars aren't always at the front (Fisher-Yates).
    for i in (1..out.len()).rev() {
        let j = rng.gen_range(0..=i);
        out.swap(i, j);
    }

    Zeroizing::new(String::from_utf8(out).expect("ascii charset is valid utf8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_and_classes() {
        let p = generate(20, true);
        assert_eq!(p.len(), 20);
        assert!(p.bytes().any(|b| b.is_ascii_lowercase()));
        assert!(p.bytes().any(|b| b.is_ascii_uppercase()));
        assert!(p.bytes().any(|b| b.is_ascii_digit()));
        assert!(p.bytes().any(|b| SYMBOLS.contains(&b)));
    }

    #[test]
    fn min_length_enforced() {
        assert_eq!(generate(3, false).len(), 8);
    }

    #[test]
    fn no_symbols_when_disabled() {
        let p = generate(30, false);
        assert!(!p.bytes().any(|b| SYMBOLS.contains(&b)));
    }

    #[test]
    fn two_passwords_differ() {
        assert_ne!(*generate(24, true), *generate(24, true));
    }
}
