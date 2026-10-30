use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("coffre-cli-test-{}-{}", std::process::id(), n));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn coffre() -> Command {
    Command::new(env!("CARGO_BIN_EXE_coffre"))
}

fn run(command: &mut Command, stdin: &str) -> std::process::Output {
    let mut child = command
        .env("COFFRE_PASSPHRASE", "test-pass")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    drop(child.stdin.take());
    child.wait_with_output().unwrap()
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn cli_end_to_end() {
    let tmp = TempDir::new();
    let path = tmp.0.join("vault.coffre");
    let path = path.to_str().unwrap();

    let out = run(coffre().args(["init", path]), "");
    assert!(
        out.status.success(),
        "init: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run(coffre().args(["add", path, "token"]), "s3cret\n");
    assert!(
        out.status.success(),
        "add: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run(coffre().args(["get", path, "token"]), "");
    assert!(out.status.success());
    assert_eq!(stdout(&out), "s3cret\n");

    let out = run(coffre().args(["list", path]), "");
    assert!(out.status.success());
    assert_eq!(stdout(&out), "token\n");

    let out = run(coffre().args(["rm", path, "token"]), "");
    assert!(out.status.success());

    let out = run(coffre().args(["list", path]), "");
    assert!(out.status.success());
    assert_eq!(stdout(&out), "");
}

#[test]
fn wrong_passphrase_fails() {
    let tmp = TempDir::new();
    let path = tmp.0.join("vault.coffre");
    let path = path.to_str().unwrap();

    let out = run(coffre().args(["init", path]), "");
    assert!(out.status.success());

    let out = coffre()
        .args(["list", path])
        .env("COFFRE_PASSPHRASE", "wrong")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).is_empty());
}

#[test]
fn unknown_command_fails() {
    let out = coffre().arg("nope").output().unwrap();
    assert!(!out.status.success());
}
