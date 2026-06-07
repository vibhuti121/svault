//! svault — a learning-grade, zero-knowledge, dual-secret (2SKD-style) password
//! vault. See README.md for the architecture and the honest "not-yet-for-real-
//! passwords" disclaimer.

mod cli;
mod clip;
mod crypto;
mod passgen;
mod totp;
mod vault;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "svault",
    version,
    about = "Zero-knowledge dual-secret password vault (learning-grade)"
)]
struct Cli {
    /// Path to the vault file (default: ~/.svault/vault.json)
    #[arg(long, global = true)]
    file: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new vault and print your Secret Key (shown ONCE).
    Init,
    /// Add or update a secret (use --generate to create a strong one).
    Add {
        name: String,
        /// Generate a strong random password instead of typing one.
        #[arg(long)]
        generate: bool,
        /// Length when --generate is used.
        #[arg(long, default_value_t = 20)]
        length: usize,
        /// Exclude symbols from the generated password.
        #[arg(long)]
        no_symbols: bool,
    },
    /// Print a secret to stdout (or --copy to clipboard with auto-clear).
    Get {
        name: String,
        /// Copy to clipboard and auto-clear instead of printing.
        #[arg(long)]
        copy: bool,
    },
    /// List entry names (values stay encrypted).
    List,
    /// Delete a secret.
    Remove { name: String },
    /// Change the master password (keeps the same Secret Key & entries).
    RotateMaster,
    /// Print a strong random password (does not touch the vault).
    Generate {
        #[arg(long, default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
    },
    /// Store a TOTP (2FA) base32 seed under a name.
    TotpAdd { name: String },
    /// Print the current TOTP (2FA) code for a stored seed.
    Totp { name: String },
}

const TOTP_PREFIX: &str = "totp/";

fn default_vault_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME not set")?;
    let mut p = PathBuf::from(home);
    p.push(".svault");
    p.push("vault.json");
    Ok(p)
}

/// Best-effort: lock all current + future pages into RAM so secrets never get
/// written to swap. Requires RLIMIT_MEMLOCK; if it fails (common for unprivileged
/// processes) we carry on — `zeroize` still wipes secrets after use. Honest about
/// being a hardening measure, not a guarantee.
fn lock_memory_best_effort() {
    #[cfg(unix)]
    unsafe {
        let _ = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
    }
}

fn main() -> Result<()> {
    lock_memory_best_effort();
    let args = Cli::parse();
    let path = match args.file {
        Some(p) => p,
        None => default_vault_path()?,
    };

    match args.cmd {
        Command::Init => cmd_init(&path),
        Command::Add {
            name,
            generate,
            length,
            no_symbols,
        } => cmd_add(&path, &name, generate, length, !no_symbols),
        Command::Get { name, copy } => cmd_get(&path, &name, copy),
        Command::List => cmd_list(&path),
        Command::Remove { name } => cmd_remove(&path, &name),
        Command::RotateMaster => cmd_rotate(&path),
        Command::Generate { length, no_symbols } => {
            println!("{}", *passgen::generate(length, !no_symbols));
            Ok(())
        }
        Command::TotpAdd { name } => cmd_totp_add(&path, &name),
        Command::Totp { name } => cmd_totp(&path, &name),
    }
}

fn cmd_init(path: &std::path::Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let pw = cli::prompt_new_password("Choose a master password: ")?;
    let secret_key = vault::init(path, &pw)?;
    let shown = cli::format_secret_key(&secret_key);

    println!("\n✅ Vault created at {}", path.display());
    println!("\n────────────────────────────────────────────────────────");
    println!("  YOUR SECRET KEY (write this down — shown only once):");
    println!("\n      {}", *shown);
    println!("\n  Without BOTH this Secret Key and your master password,");
    println!("  the vault is UNRECOVERABLE. We never store the Secret Key.");
    println!("────────────────────────────────────────────────────────\n");
    Ok(())
}

fn cmd_add(
    path: &std::path::Path,
    name: &str,
    generate: bool,
    length: usize,
    symbols: bool,
) -> Result<()> {
    let pw = cli::prompt_password("Master password: ")?;
    let sk = cli::prompt_secret_key()?;
    let mut v = vault::unlock(path, &pw, &sk)?;

    if generate {
        let secret = passgen::generate(length, symbols);
        v.put(name, &secret)?;
        v.save(path)?;
        println!("✅ Saved '{name}' with a generated password:\n{}", *secret);
    } else {
        let secret = cli::prompt_password(&format!("Secret value for '{name}': "))?;
        v.put(name, &secret)?;
        v.save(path)?;
        println!("✅ Saved '{name}'.");
    }
    Ok(())
}

fn cmd_get(path: &std::path::Path, name: &str, copy: bool) -> Result<()> {
    let pw = cli::prompt_password("Master password: ")?;
    let sk = cli::prompt_secret_key()?;
    let v = vault::unlock(path, &pw, &sk)?;
    let secret = v.get(name)?;
    if copy {
        clip::copy_with_autoclear(&secret, clip::DEFAULT_CLEAR_SECS)?;
    } else {
        println!("{}", *secret);
    }
    Ok(())
}

fn cmd_list(path: &std::path::Path) -> Result<()> {
    let pw = cli::prompt_password("Master password: ")?;
    let sk = cli::prompt_secret_key()?;
    let v = vault::unlock(path, &pw, &sk)?;
    let names = v.list();
    if names.is_empty() {
        println!("(vault is empty)");
    } else {
        for n in names {
            println!("{n}");
        }
    }
    Ok(())
}

fn cmd_remove(path: &std::path::Path, name: &str) -> Result<()> {
    let pw = cli::prompt_password("Master password: ")?;
    let sk = cli::prompt_secret_key()?;
    let mut v = vault::unlock(path, &pw, &sk)?;
    if v.remove(name) {
        v.save(path)?;
        println!("✅ Removed '{name}'.");
    } else {
        println!("No entry named '{name}'.");
    }
    Ok(())
}

fn cmd_rotate(path: &std::path::Path) -> Result<()> {
    let pw = cli::prompt_password("Current master password: ")?;
    let sk = cli::prompt_secret_key()?;
    let mut v = vault::unlock(path, &pw, &sk)?;
    let new_pw = cli::prompt_new_password("New master password: ")?;
    vault::rotate_master(&mut v, &sk, &new_pw)?;
    v.save(path)?;
    println!("✅ Master password changed. Same Secret Key, same entries.");
    Ok(())
}

fn cmd_totp_add(path: &std::path::Path, name: &str) -> Result<()> {
    let pw = cli::prompt_password("Master password: ")?;
    let sk = cli::prompt_secret_key()?;
    let mut v = vault::unlock(path, &pw, &sk)?;
    let seed = cli::prompt_password(&format!("TOTP base32 seed for '{name}': "))?;
    // Validate the seed decodes before storing, so we fail early on a typo.
    totp::decode_secret(seed.trim())?;
    v.put(&format!("{TOTP_PREFIX}{name}"), seed.trim())?;
    v.save(path)?;
    println!("✅ Stored TOTP seed for '{name}'. Get codes with: svault totp {name}");
    Ok(())
}

fn cmd_totp(path: &std::path::Path, name: &str) -> Result<()> {
    let pw = cli::prompt_password("Master password: ")?;
    let sk = cli::prompt_secret_key()?;
    let v = vault::unlock(path, &pw, &sk)?;
    let seed = v
        .get(&format!("{TOTP_PREFIX}{name}"))
        .with_context(|| format!("no TOTP seed stored for '{name}' (add it with `totp-add`)"))?;
    let secret = totp::decode_secret(seed.trim())?;
    let now = totp::now_unix()?;
    let code = totp::code_at(&secret, now, totp::DEFAULT_PERIOD, totp::DEFAULT_DIGITS)?;
    let remaining = totp::seconds_remaining(now, totp::DEFAULT_PERIOD);
    println!("{code}  (valid {remaining}s)");
    Ok(())
}
