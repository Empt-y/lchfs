//! Where the CLI gets secrets from (ARCHITECTURE.md §18): passphrases,
//! TPM PINs and recipient identities.
//!
//! A passphrase is never an argument or an environment variable -- both are
//! readable by other processes (`ps`, `/proc/<pid>/environ`). It comes from
//! a file, an inherited file descriptor, a no-echo prompt on the
//! controlling terminal, or an askpass helper, in that order of preference.
//! Every buffer holding one is zeroed when dropped.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub type Secret = Zeroizing<Vec<u8>>;

/// Where a passphrase may be read from without asking anyone.
#[derive(Debug, Clone, Default)]
pub struct Source {
    pub file: Option<PathBuf>,
    pub fd: Option<i32>,
}

impl Source {
    pub fn is_given(&self) -> bool {
        self.file.is_some() || self.fd.is_some()
    }

    /// The passphrase from the file or descriptor, if one was named.
    pub fn read(&self) -> anyhow::Result<Option<Secret>> {
        let (bytes, from) = match (&self.file, self.fd) {
            (Some(path), _) => (
                std::fs::read(path).map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?,
                path.display().to_string(),
            ),
            // Through /dev/fd rather than adopting the raw descriptor: no
            // unsafe, and a pipe or a regular file reads the same way.
            (None, Some(fd)) => (
                std::fs::read(format!("/dev/fd/{fd}")).map_err(|e| anyhow::anyhow!("reading descriptor {fd}: {e}"))?,
                format!("descriptor {fd}"),
            ),
            (None, None) => return Ok(None),
        };
        let secret = strip_newline(Zeroizing::new(bytes));
        if secret.is_empty() {
            anyhow::bail!("the passphrase from {from} is empty");
        }
        Ok(Some(secret))
    }
}

/// One trailing `\n` or `\r\n` is the file's line ending, not part of the
/// passphrase; anything else is kept exactly.
fn strip_newline(mut s: Secret) -> Secret {
    if s.last() == Some(&b'\n') {
        s.pop();
        if s.last() == Some(&b'\r') {
            s.pop();
        }
    }
    s
}

/// True when a person can be asked: a controlling terminal or an askpass
/// helper exists.
pub fn can_prompt() -> bool {
    std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").is_ok() || askpass_program().is_some()
}

fn askpass_program() -> Option<String> {
    ["LCHFS_ASKPASS", "SSH_ASKPASS"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|p| !p.is_empty()))
}

/// Asks for a secret: on the controlling terminal with echo off, else
/// through the askpass helper, else an error naming the alternatives.
pub fn prompt(prompt: &str) -> anyhow::Result<Secret> {
    let secret = match std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(tty) => prompt_tty(tty, prompt)?,
        Err(_) => match askpass_program() {
            Some(program) => prompt_askpass(&program, prompt)?,
            None => anyhow::bail!(
                "{prompt} needs a terminal or an askpass helper (LCHFS_ASKPASS/SSH_ASKPASS); \
                 or pass it with --passphrase-file or --passphrase-fd"
            ),
        },
    };
    if secret.is_empty() {
        anyhow::bail!("empty passphrase");
    }
    Ok(secret)
}

/// Asks twice for a new secret and insists they match.
pub fn prompt_new(what: &str) -> anyhow::Result<Secret> {
    let first = prompt(&format!("New {what}: "))?;
    let second = prompt(&format!("Repeat the new {what}: "))?;
    if *first != *second {
        anyhow::bail!("the two entries of the new {what} differ");
    }
    Ok(first)
}

/// A new passphrase: from `source` if given, else asked for twice.
pub fn new_passphrase(source: &Source) -> anyhow::Result<Secret> {
    match source.read()? {
        Some(s) => Ok(s),
        None => prompt_new("passphrase"),
    }
}

fn prompt_tty(tty: std::fs::File, prompt: &str) -> anyhow::Result<Secret> {
    use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
    let original = tcgetattr(&tty)?;
    let mut quiet = original.clone();
    quiet.local_flags.remove(LocalFlags::ECHO);
    quiet.local_flags.insert(LocalFlags::ECHONL);
    (&tty).write_all(prompt.as_bytes())?;
    (&tty).flush()?;
    tcsetattr(&tty, SetArg::TCSAFLUSH, &quiet)?;
    // Echo comes back on however the read ends.
    struct Restore<'a>(&'a std::fs::File, nix::sys::termios::Termios);
    impl Drop for Restore<'_> {
        fn drop(&mut self) {
            let _ = nix::sys::termios::tcsetattr(self.0, nix::sys::termios::SetArg::TCSAFLUSH, &self.1);
        }
    }
    let _restore = Restore(&tty, original);
    let mut line = Zeroizing::new(Vec::new());
    BufReader::new(&tty).read_until(b'\n', &mut line)?;
    Ok(strip_newline(line))
}

fn prompt_askpass(program: &str, prompt: &str) -> anyhow::Result<Secret> {
    let out = std::process::Command::new(program)
        .arg(prompt)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| anyhow::anyhow!("running askpass helper {program}: {e}"))?;
    let stdout = Zeroizing::new(out.stdout);
    if !out.status.success() {
        anyhow::bail!("askpass helper {program} was cancelled or failed ({})", out.status);
    }
    Ok(strip_newline(stdout))
}

/// Reads a recipient identity (the secret half of a recipient key pair).
/// Refused if anyone but its owner can read it, as ssh refuses a private
/// key: a world-readable identity is a leaked one.
pub fn read_identity(path: &Path) -> anyhow::Result<lchfs_crypto::slots::recipient::Identity> {
    let meta = std::fs::metadata(path).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    if meta.permissions().mode() & 0o077 != 0 {
        anyhow::bail!(
            "{} is readable by others (mode {:o}); an identity must be private (chmod 600)",
            path.display(),
            meta.permissions().mode() & 0o777
        );
    }
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?);
    lchfs_crypto::slots::recipient::Identity::parse(text.trim())
        .map_err(|e| anyhow::anyhow!("{} is not an lchfs identity: {e}", path.display()))
}

/// Reads a recipient (public key) file.
pub fn read_recipient(path: &Path) -> anyhow::Result<lchfs_crypto::slots::recipient::Recipient> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    lchfs_crypto::slots::recipient::Recipient::parse(text.trim())
        .map_err(|e| anyhow::anyhow!("{} is not an lchfs recipient: {e}", path.display()))
}

/// Writes a new key pair: `out` (the identity, 0600, created exclusively)
/// and `out.pub` (the recipient).
pub fn write_identity(out: &Path) -> anyhow::Result<PathBuf> {
    use std::os::unix::fs::OpenOptionsExt;
    let identity = lchfs_crypto::slots::recipient::Identity::generate();
    let public = PathBuf::from(format!("{}.pub", out.display()));
    if public.exists() {
        anyhow::bail!("{} already exists", public.display());
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .map_err(|e| anyhow::anyhow!("{}: {e}", out.display()))?;
    let text = Zeroizing::new(identity.to_text());
    f.write_all(text.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    std::fs::write(&public, format!("{}\n", identity.recipient().to_text()))?;
    Ok(public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_line_ending_is_stripped_and_nothing_else() {
        let s = |b: &[u8]| strip_newline(Zeroizing::new(b.to_vec())).to_vec();
        assert_eq!(s(b"pass\n"), b"pass");
        assert_eq!(s(b"pass\r\n"), b"pass");
        assert_eq!(s(b"pass\n\n"), b"pass\n");
        assert_eq!(s(b" pass "), b" pass ");
    }
}
