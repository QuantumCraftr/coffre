use std::io::{self, IsTerminal, Read, Write};
use std::path::Path;
use std::process::ExitCode;

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
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("coffre: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), CliError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        return Err(CliError::Usage(usage().to_string()));
    };
    match command.as_str() {
        "init" => cmd_init(rest),
        "add" => cmd_add(rest),
        "get" => cmd_get(rest),
        "list" => cmd_list(rest),
        "rm" => cmd_rm(rest),
        "help" | "-h" | "--help" => {
            println!("{}", usage());
            Ok(())
        }
        other => Err(CliError::Usage(format!(
            "unknown command: {other}\n\n{}",
            usage()
        ))),
    }
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

fn usage() -> &'static str {
    "usage: coffre <command> [args]

commands:
  init <path>            create an encrypted vault
  add  <path> <name>     add or replace a secret (value from stdin or prompt)
  get  <path> <name>     print a secret value
  list <path>            list secret names
  rm   <path> <name>     remove a secret

passphrase: prompted on the terminal, or read from COFFRE_PASSPHRASE for automation"
}
