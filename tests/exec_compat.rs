use std::fs;

use assert_cmd::Command;

#[test]
fn exec_uses_container_path_without_merging_payload_environment() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("state");
    let container = root.join("demo");
    fs::create_dir_all(&container).unwrap();
    fs::write(
        container.join("status.json"),
        serde_json::to_vec(&serde_json::json!({
            "id": "demo",
            "pid": std::process::id(),
            "status": "running",
            "bundle": "/bundle",
            "created": "0",
            "owner": "tester",
            "annotations": {},
            "ociVersion": "1.3.0"
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        container.join("config.json"),
        serde_json::to_vec(&serde_json::json!({
            "ociVersion": "1.3.0",
            "process": {
                "cwd": "/",
                "args": ["ignored"],
                "env": ["PATH=/usr/bin:/bin", "BASE=hidden"]
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let process = temporary.path().join("process.json");
    fs::write(
        &process,
        serde_json::to_vec(&serde_json::json!({
            "cwd": "/",
            "args": ["env"],
            "env": ["DUP=one", "DUP=two", "ONLY=value"]
        }))
        .unwrap(),
    )
    .unwrap();

    #[allow(deprecated)]
    let mut command = Command::cargo_bin("ll-box").unwrap();
    command
        .args(["--root"])
        .arg(&root)
        .args(["exec", "--process"])
        .arg(&process)
        .arg("demo")
        .assert()
        .success()
        .stdout("DUP=one\nDUP=two\nONLY=value\n");
}

#[test]
fn kill_uses_the_compatibility_status_without_internal_youki_state() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("state");
    let container = root.join("demo");
    fs::create_dir_all(&container).unwrap();
    fs::write(
        container.join("status.json"),
        serde_json::to_vec(&serde_json::json!({
            "id": "demo",
            "pid": std::process::id(),
            "status": "running",
            "bundle": "/bundle",
            "created": "0",
            "owner": "tester",
            "annotations": {},
            "ociVersion": "1.3.0"
        }))
        .unwrap(),
    )
    .unwrap();

    #[allow(deprecated)]
    let mut command = Command::cargo_bin("ll-box").unwrap();
    command
        .args(["--root"])
        .arg(&root)
        .args(["kill", "demo", "0"])
        .assert()
        .success();
}
