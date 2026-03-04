//! Integration tests for fanotify_audit.
//!
//! Note: most fanotify tests require root / CAP_SYS_ADMIN.
//! Tests that need privileges are gated behind a `privileged` feature
//! or check for permissions at runtime and skip gracefully.

use std::process::Command;

#[test]
fn cli_help_works() {
    let output = Command::new(env!("CARGO_BIN_EXE_fanotify_audit"))
        .arg("--help")
        .output()
        .expect("failed to run binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fanotify audit"));
}

#[test]
fn cli_watch_help_works() {
    let output = Command::new(env!("CARGO_BIN_EXE_fanotify_audit"))
        .args(["watch", "--help"])
        .output()
        .expect("failed to run binary");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--path"));
    assert!(stdout.contains("--mark-type"));
    assert!(stdout.contains("--events"));
}
