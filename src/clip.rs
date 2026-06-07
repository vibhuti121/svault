//! clip.rs — copy a secret to the clipboard and auto-clear it after a delay.
//!
//! TEACHING NOTE: the clipboard is a common leak path — other apps, sync tools,
//! and clipboard-history utilities can read it. So we (a) put the secret there
//! only on explicit request, and (b) overwrite it after a short window. We can't
//! defeat a clipboard-history manager that already snapshotted it — that's an OS
//! limitation we call out honestly rather than pretend to solve.

use anyhow::{Context, Result};
use std::time::Duration;

pub const DEFAULT_CLEAR_SECS: u64 = 15;

/// Copy `text` to the clipboard, wait `secs`, then clear it. Blocks for the
/// duration so the clear actually happens before the process exits (on most
/// platforms the clipboard is owned by the OS and survives process exit, so a
/// fire-and-forget clear from a dying process would be unreliable).
pub fn copy_with_autoclear(text: &str, secs: u64) -> Result<()> {
    let mut cb = arboard::Clipboard::new().context("open clipboard")?;
    cb.set_text(text.to_owned()).context("write clipboard")?;
    // Honest wording: there is no SIGINT handler, so Ctrl-C aborts BEFORE the
    // clear runs and the secret stays on the clipboard. Keep the window open.
    println!("📋 Copied to clipboard. Auto-clearing in {secs}s — keep this window open (Ctrl-C aborts WITHOUT clearing).");

    std::thread::sleep(Duration::from_secs(secs));

    // Overwrite then clear — belt and suspenders.
    let _ = cb.set_text(String::new());
    cb.clear().context("clear clipboard")?;
    println!("🧹 Clipboard cleared.");
    Ok(())
}
