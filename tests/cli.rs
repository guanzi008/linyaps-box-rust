use std::fs;
use std::os::unix::fs::PermissionsExt;

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn version_matches_original_shape() {
    let mut command = Command::cargo_bin("ll-box").unwrap();
    command
        .arg("--version")
        .assert()
        .success()
        .stdout("ll-box version 2.3.0-dev-\nspec 1.3.0\n\n");
}

#[test]
fn help_has_no_runtime_directory_side_effect() {
    let runtime = tempfile::tempdir().unwrap();
    let expected = runtime.path().join("linglong/box");
    let mut command = Command::cargo_bin("ll-box").unwrap();
    command
        .env("XDG_RUNTIME_DIR", runtime.path())
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("SUBCOMMANDS:"));
    assert!(!expected.exists());
}

#[test]
fn empty_list_prints_original_header() {
    let runtime = tempfile::tempdir().unwrap();
    let root = runtime.path().join("state");
    let mut command = Command::cargo_bin("ll-box").unwrap();
    command
        .args(["--root", root.to_str().unwrap(), "list"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("NAME PID"));
    assert!(fs::metadata(root).unwrap().is_dir());
}

#[test]
fn nonempty_list_matches_original_json_and_table_formatting() {
    let runtime = tempfile::tempdir().unwrap();
    let root = runtime.path().join("state");
    let container = root.join("demo");
    fs::create_dir_all(&container).unwrap();
    fs::write(
        container.join("status.json"),
        serde_json::to_vec(&serde_json::json!({
            "id": "demo",
            "pid": std::process::id(),
            "status": "running",
            "bundle": "/bundle path",
            "created": "0",
            "owner": "tester",
            "annotations": {},
            "ociVersion": "1.3.0"
        }))
        .unwrap(),
    )
    .unwrap();

    let expected_json = format!(
        "[\n    {{\n        \"annotations\": {{}},\n        \"bundle\": \"/bundle path\",\n        \"created\": \"0\",\n        \"id\": \"demo\",\n        \"ociVersion\": \"1.3.0\",\n        \"owner\": \"tester\",\n        \"pid\": {},\n        \"status\": \"running\"\n    }}\n]\n",
        std::process::id()
    );
    let mut json = Command::cargo_bin("ll-box").unwrap();
    json.args(["--root", root.to_str().unwrap(), "list", "--format", "json"])
        .assert()
        .success()
        .stdout(expected_json);

    let mut table = Command::cargo_bin("ll-box").unwrap();
    table
        .args(["--root", root.to_str().unwrap(), "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "demo{:<10}running  \"/bundle path\"",
            std::process::id()
        )));
}

#[test]
fn ns_last_pid_extension_has_no_hidden_public_cli() {
    let rootfs = tempfile::tempdir().unwrap();
    let directory = rootfs.path().join("proc/sys/kernel");
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("ns_last_pid"), "0").unwrap();
    let mut command = Command::cargo_bin("ll-box").unwrap();
    command
        .args([
            "__internal-ns-last-pid",
            rootfs.path().to_str().unwrap(),
            "3210",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("A subcommand is required"));
    assert_eq!(
        fs::read_to_string(directory.join("ns_last_pid")).unwrap(),
        "0"
    );
}

#[test]
fn explicit_file_sink_receives_json_logs() {
    let temporary = tempfile::tempdir().unwrap();
    let invalid_root = temporary.path().join("not-a-directory");
    let log = temporary.path().join("runtime.log");
    fs::write(&invalid_root, "file").unwrap();

    let mut command = Command::cargo_bin("ll-box").unwrap();
    command
        .args([
            "--root",
            invalid_root.to_str().unwrap(),
            "--log-format",
            "json",
            "--log",
            &format!("file:{}", log.display()),
            "list",
        ])
        .assert()
        .failure()
        .stderr("");

    let value: serde_json::Value =
        serde_json::from_str(fs::read_to_string(&log).unwrap().trim()).unwrap();
    assert_eq!(value["level"], "ERROR");
    assert!(value["msg"].as_str().unwrap().starts_with("Error: "));
    assert_eq!(value["function"], "main");
    assert_eq!(value["file"], "main.rs");
    assert!(value["line"].as_u64().unwrap() > 0);
    assert_eq!(
        fs::metadata(log).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn parse_errors_match_frozen_cli11_text() {
    let cases: &[(&[&str], &str)] = &[
        (&["--root", "/tmp"], "A subcommand is required"),
        (&["--bad-option"], "A subcommand is required"),
        (
            &["--wat", "list"],
            "ll-box: The following argument was not expected: --wat",
        ),
        (
            &["list", "--log-level", "debug"],
            "list: The following arguments were not expected: --log-level debug",
        ),
        (
            &["--cgroup-manager", "nope", "list"],
            "--cgroup-manager: Check nope value in {cgroupfs->cgroupfs,systemd->systemd,disabled->disabled} OR {2,1,0} FAILED",
        ),
        (
            &["list", "--format", "nope"],
            "--format: Check nope value in {json->1,table->0} OR {1,0} FAILED",
        ),
        (
            &["run", "-b", "/does/not/exist", "demo"],
            "--bundle: Directory does not exist: /does/not/exist",
        ),
        (
            &["run", "-b", "/etc/passwd", "demo"],
            "--bundle: Directory is actually a file: /etc/passwd",
        ),
        (
            &["run", "--preserve-fds", "-1", "demo"],
            "--preserve-fds: Value -1 not in range [0 - 1.79769e+308]",
        ),
        (
            &["run", "--preserve-fds", "1.0", "demo"],
            "Could not convert: --preserve-fds = 1.0",
        ),
        (
            &["run", "--console-socket", "/does/not/exist", "demo"],
            "--console-socket: console-socket must be an existing socket file",
        ),
        (
            &["exec", "-u", "1:2:3", "demo", "true"],
            "--user: invalid GID: Success",
        ),
        (
            &["exec", "-e", "BAD", "--", "demo", "true"],
            "--env: invalid env: BAD",
        ),
        (
            &["exec", "-c", "CAP_NOPE", "--", "demo", "true"],
            "--cap: --cap: invalid capability: CAP_NOPE",
        ),
        (
            &["exec", "-p", "/tmp", "demo"],
            "--process: File is actually a directory: /tmp",
        ),
        (
            &["kill", "demo", "--bad"],
            "kill: The following argument was not expected: --bad",
        ),
        (
            &["kill", "demo", "65"],
            "SIGNAL: SIGNAL: signal number out of range: 65",
        ),
        (
            &["--root", "/a", "--root", "/b", "list"],
            "--root: At most 1 required but received 2",
        ),
        (
            &["--cee-syslog=maybe", "list"],
            "Could not convert: --cee-syslog = maybe",
        ),
    ];
    for (arguments, expected) in cases {
        let mut command = Command::cargo_bin("ll-box").unwrap();
        command
            .args(*arguments)
            .assert()
            .failure()
            .stdout("")
            .stderr(format!(
                "{expected}\nRun with --help for more information.\n"
            ));
    }
}

#[test]
fn variadic_logs_and_numeric_flags_match_cli11() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("state");
    let log = temporary.path().join("extra.log");
    let mut command = Command::cargo_bin("ll-box").unwrap();
    command
        .args([
            "--root",
            root.to_str().unwrap(),
            "--log",
            "stderr",
            log.to_str().unwrap(),
            "--cee-syslog=1",
            "list",
        ])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("NAME PID"));
    assert!(log.is_file());
}

#[test]
fn fatal_level_suppresses_nonfatal_errors() {
    let runtime = tempfile::tempdir().unwrap();
    let mut command = Command::cargo_bin("ll-box").unwrap();
    command
        .env("XDG_RUNTIME_DIR", runtime.path())
        .args(["--log-level", "fatal", "exec", "missing", "true"])
        .assert()
        .failure()
        .stderr("");
}
