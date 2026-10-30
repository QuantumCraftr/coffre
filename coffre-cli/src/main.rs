use std::ffi::OsString;
use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::process::{Command, ExitCode};

use coffre_core::crypto::KdfParams;
use coffre_core::vault::{Vault, VaultError};
use zeroize::Zeroizing;

#[derive(Debug)]
enum CliError {
    Usage(String),
    Vault(VaultError),
    Io(io::Error),
    PassphraseMismatch,
    NotFound(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Usage(msg) => write!(f, "{msg}"),
            CliError::Vault(e) => write!(f, "{e}"),
            CliError::Io(e) => write!(f, "{e}"),
            CliError::PassphraseMismatch => write!(f, "passphrases do not match"),
            CliError::NotFound(name) => write!(f, "secret not found: {name}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<VaultError> for CliError {
    fn from(e: VaultError) -> Self {
        CliError::Vault(e)
    }
}

impl From<io::Error> for CliError {
    fn from(e: io::Error) -> Self {
        CliError::Io(e)
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("coffre: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, CliError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        return Err(CliError::Usage(usage().to_string()));
    };
    match command.as_str() {
        "init" => cmd_init(rest)?,
        "add" => cmd_add(rest)?,
        "get" => cmd_get(rest)?,
        "list" => cmd_list(rest)?,
        "rm" => cmd_rm(rest)?,
        "run" => return cmd_run(rest),
        "help" | "-h" | "--help" => {
            println!("{}", usage());
        }
        other => {
            return Err(CliError::Usage(format!(
                "unknown command: {other}\n\n{}",
                usage()
            )));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_init(rest: &[String]) -> Result<(), CliError> {
    let path = one_arg(rest, "init <path>")?;
    let passphrase = read_passphrase(true)?;
    Vault::create(Path::new(path), passphrase.as_bytes(), KdfParams::default())?;
    Ok(())
}

fn cmd_add(rest: &[String]) -> Result<(), CliError> {
    let (path, name) = two_args(rest, "add <path> <name>")?;
    let passphrase = read_passphrase(false)?;
    let value = read_value()?;
    let mut vault = Vault::open(Path::new(path), passphrase.as_bytes())?;
    vault.add(name, value.as_slice());
    vault.save()?;
    Ok(())
}

fn cmd_get(rest: &[String]) -> Result<(), CliError> {
    let (path, name) = two_args(rest, "get <path> <name>")?;
    let passphrase = read_passphrase(false)?;
    let vault = Vault::open(Path::new(path), passphrase.as_bytes())?;
    let Some(value) = vault.get(name) else {
        return Err(CliError::NotFound(name.to_string()));
    };
    let mut stdout = io::stdout().lock();
    stdout.write_all(value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn cmd_list(rest: &[String]) -> Result<(), CliError> {
    let path = one_arg(rest, "list <path>")?;
    let passphrase = read_passphrase(false)?;
    let vault = Vault::open(Path::new(path), passphrase.as_bytes())?;
    for name in vault.list() {
        println!("{name}");
    }
    Ok(())
}

fn cmd_rm(rest: &[String]) -> Result<(), CliError> {
    let (path, name) = two_args(rest, "rm <path> <name>")?;
    let passphrase = read_passphrase(false)?;
    let mut vault = Vault::open(Path::new(path), passphrase.as_bytes())?;
    if !vault.remove(name) {
        return Err(CliError::NotFound(name.to_string()));
    }
    vault.save()?;
    Ok(())
}

fn cmd_run(rest: &[String]) -> Result<ExitCode, CliError> {
    let separator = rest
        .iter()
        .position(|arg| arg.as_str() == "--")
        .ok_or_else(|| CliError::Usage(run_usage()))?;
    if separator == 0 {
        return Err(CliError::Usage(run_usage()));
    }
    let path = &rest[0];
    let names = &rest[1..separator];
    let command = &rest[separator + 1..];
    if command.is_empty() {
        return Err(CliError::Usage(run_usage()));
    }

    let passphrase = read_passphrase(false)?;
    let vault = Vault::open(Path::new(path), passphrase.as_bytes())?;

    let mut values = Vec::new();
    for name in names {
        if !is_env_name(name) {
            return Err(CliError::Usage(format!(
                "not a valid environment variable name: {name}"
            )));
        }
        let Some(value) = vault.get(name) else {
            return Err(CliError::NotFound(name.clone()));
        };
        values.push((name.clone(), Zeroizing::new(value.to_vec())));
    }

    let mut child = Command::new(command[0].as_str());
    child.args(&command[1..]);
    for (name, value) in &values {
        child.env(name.as_str(), env_value(value.as_slice()));
    }

    let status = child.status()?;
    Ok(exit_code_from(status))
}

fn is_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(unix)]
fn env_value(bytes: &[u8]) -> OsString {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::OsStr::from_bytes(bytes).to_os_string()
}

#[cfg(not(unix))]
fn env_value(bytes: &[u8]) -> OsString {
    OsString::from(String::from_utf8_lossy(bytes).into_owned())
}

fn exit_code_from(status: std::process::ExitStatus) -> ExitCode {
    match status.code() {
        Some(code) if (0..=255).contains(&code) => ExitCode::from(code as u8),
        _ => ExitCode::FAILURE,
    }
}

fn read_passphrase(confirm: bool) -> Result<Zeroizing<String>, CliError> {
    if let Ok(from_env) = std::env::var("COFFRE_PASSPHRASE") {
        return Ok(Zeroizing::new(from_env));
    }
    let passphrase = Zeroizing::new(rpassword::prompt_password("Passphrase: ")?);
    if confirm {
        let again = rpassword::prompt_password("Confirm passphrase: ")?;
        if passphrase.as_str() != again.as_str() {
            return Err(CliError::PassphraseMismatch);
        }
    }
    Ok(passphrase)
}

fn read_value() -> Result<Zeroizing<Vec<u8>>, CliError> {
    if io::stdin().is_terminal() {
        let value = rpassword::prompt_password("Secret value: ")?;
        Ok(Zeroizing::new(value.into_bytes()))
    } else {
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer)?;
        if buffer.last() == Some(&b'\n') {
            buffer.pop();
            if buffer.last() == Some(&b'\r') {
                buffer.pop();
            }
        }
        Ok(Zeroizing::new(buffer))
    }
}

fn one_arg<'a>(rest: &'a [String], usage: &str) -> Result<&'a str, CliError> {
    match rest {
        [arg] => Ok(arg.as_str()),
        _ => Err(CliError::Usage(format!("usage: coffre {usage}"))),
    }
}

fn two_args<'a>(rest: &'a [String], usage: &str) -> Result<(&'a str, &'a str), CliError> {
    match rest {
        [first, second] => Ok((first.as_str(), second.as_str())),
        _ => Err(CliError::Usage(format!("usage: coffre {usage}"))),
    }
}

fn run_usage() -> String {
    "usage: coffre run <path> [name...] -- <command> [args...]".to_string()
}

fn usage() -> &'static str {
    "usage: coffre <command> [args]

commands:
  init <path>            create an encrypted vault
  add  <path> <name>     add or replace a secret (value from stdin or prompt)
  get  <path> <name>     print a secret value
  list <path>            list secret names
  rm   <path> <name>     remove a secret
  run  <path> [name...] -- <command> [args...]
                         run a command with secrets injected as env vars

passphrase: prompted on the terminal, or read from COFFRE_PASSPHRASE for automation"
}
