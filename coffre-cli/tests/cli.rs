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

#[test]
fn run_injects_requested_secrets_only() {
    let tmp = TempDir::new();
    let path = tmp.0.join("vault.coffre");
    let path = path.to_str().unwrap();

    assert!(run(coffre().args(["init", path]), "").status.success());
    assert!(
        run(coffre().args(["add", path, "API_KEY"]), "s3cret\n")
            .status
            .success()
    );
    assert!(
        run(coffre().args(["add", path, "OTHER"]), "nope\n")
            .status
            .success()
    );

    let out = run(
        coffre().args([
            "run",
            path,
            "API_KEY",
            "--",
            "sh",
            "-c",
            "printf %s \"$API_KEY\"",
        ]),
        "",
    );
    assert!(
        out.status.success(),
        "run: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(stdout(&out), "s3cret");

    let out = run(
        coffre().args([
            "run",
            path,
            "API_KEY",
            "--",
            "sh",
            "-c",
            "printf %s \"${OTHER:-unset}\"",
        ]),
        "",
    );
    assert!(out.status.success());
    assert_eq!(stdout(&out), "unset");
}

#[test]
fn run_propagates_exit_code() {
    let tmp = TempDir::new();
    let path = tmp.0.join("vault.coffre");
    let path = path.to_str().unwrap();
    assert!(run(coffre().args(["init", path]), "").status.success());

    let out = run(coffre().args(["run", path, "--", "sh", "-c", "exit 7"]), "");
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn run_does_not_leak_passphrase_to_child() {
    let tmp = TempDir::new();
    let path = tmp.0.join("vault.coffre");
    let path = path.to_str().unwrap();
    assert!(run(coffre().args(["init", path]), "").status.success());

    let out = run(
        coffre().args([
            "run",
            path,
            "--",
            "sh",
            "-c",
            "printf %s \"${COFFRE_PASSPHRASE:-unset}\"",
        ]),
        "",
    );
    assert!(out.status.success());
    assert_eq!(stdout(&out), "unset");
}

#[test]
fn init_rejects_empty_passphrase() {
    let tmp = TempDir::new();
    let path = tmp.0.join("vault.coffre");
    let path = path.to_str().unwrap();
    let out = coffre()
        .args(["init", path])
        .env("COFFRE_PASSPHRASE", "")
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn add_rejects_name_with_newline() {
    let tmp = TempDir::new();
    let path = tmp.0.join("vault.coffre");
    let path = path.to_str().unwrap();
    assert!(run(coffre().args(["init", path]), "").status.success());
    let out = run(coffre().args(["add", path, "bad\nname"]), "v");
    assert!(!out.status.success());
}

#[cfg(unix)]
#[test]
fn non_utf8_argument_fails_gracefully() {
    use std::os::unix::ffi::OsStrExt;
    let bad = std::ffi::OsStr::from_bytes(b"\xff");
    let out = coffre().arg(bad).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn add_rejects_name_with_control_characters() {
    let tmp = TempDir::new();
    let path = tmp.0.join("vault.coffre");
    let path = path.to_str().unwrap();
    assert!(run(coffre().args(["init", path]), "").status.success());
    let out = run(coffre().args(["add", path, "bad\x1b[2Jname"]), "v");
    assert!(!out.status.success());
}

#[test]
fn add_reads_large_value_from_stdin() {
    // Plus grand que le tampon initial : exerce la croissance du buffer de lecture.
    let tmp = TempDir::new();
    let path = tmp.0.join("vault.coffre");
    let path = path.to_str().unwrap();
    assert!(run(coffre().args(["init", path]), "").status.success());
    let value: String = (0..100_000)
        .map(|i| (b'a' + (i % 26) as u8) as char)
        .collect();
    let out = run(coffre().args(["add", path, "big"]), &value);
    assert!(out.status.success());
    let out = run(coffre().args(["get", path, "big"]), "");
    assert_eq!(stdout(&out), format!("{value}\n"));
}

#[test]
fn run_reports_missing_command() {
    let tmp = TempDir::new();
    let path = tmp.0.join("vault.coffre");
    let path = path.to_str().unwrap();
    assert!(run(coffre().args(["init", path]), "").status.success());
    let out = run(
        coffre().args(["run", path, "--", "coffre-no-such-command"]),
        "",
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot run 'coffre-no-such-command'"));
}
