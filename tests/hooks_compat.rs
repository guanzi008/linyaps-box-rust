use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use libcontainer::container::{ContainerStatus, State};
use oci_spec::runtime::HookBuilder;

#[test]
fn hook_receives_frozen_linyaps_state_and_empty_default_environment() {
    let temporary = tempfile::tempdir().unwrap();
    let state_output = temporary.path().join("state.json");
    let environment_output = temporary.path().join("environment.txt");
    let original_bundle = temporary.path().join("original-bundle");
    let mut annotations = HashMap::new();
    annotations.insert(
        "cn.org.linyaps.internal.hook-state.original-bundle".to_string(),
        original_bundle.display().to_string(),
    );
    annotations.insert(
        "cn.org.linyaps.internal.hook-state.created".to_string(),
        "123456789".to_string(),
    );
    annotations.insert(
        "cn.org.linyaps.internal.hook-state.owner".to_string(),
        "tester".to_string(),
    );
    annotations.insert("user.annotation".to_string(), "hidden".to_string());
    let state = State {
        oci_version: "1.1.0".to_string(),
        id: "demo".to_string(),
        status: ContainerStatus::Creating,
        pid: None,
        bundle: PathBuf::from("/temporary/prepared-bundle"),
        annotations: Some(annotations),
        ..State::default()
    };
    let hook = HookBuilder::default()
        .path("/bin/sh")
        .args(vec![
            "hook".to_string(),
            "-c".to_string(),
            "cat > \"$STATE_OUT\"; printf %s \"${LEAKED-unset}\" > \"$ENV_OUT\"".to_string(),
        ])
        .env(vec![
            format!("STATE_OUT={}", state_output.display()),
            format!("ENV_OUT={}", environment_output.display()),
        ])
        .build()
        .unwrap();
    let defaults = HashMap::from([("LEAKED".to_string(), "bad".to_string())]);

    libcontainer::hooks::run_hooks(Some(&vec![hook]), Some(&state), None, None, Some(&defaults))
        .unwrap();

    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(state_output).unwrap()).unwrap();
    assert_eq!(value["ociVersion"], "1.3.0");
    assert_eq!(value["id"], "demo");
    assert_eq!(value["status"], "created");
    assert_eq!(value["bundle"], original_bundle.display().to_string());
    assert_eq!(value["created"], "123456789");
    assert_eq!(value["owner"], "tester");
    assert_eq!(value["annotations"], serde_json::json!({}));
    assert!(value["pid"].as_i64().unwrap() > 0);
    assert_eq!(fs::read_to_string(environment_output).unwrap(), "unset");
}

#[test]
fn poststop_hooks_continue_after_failures() {
    let temporary = tempfile::tempdir().unwrap();
    let marker = temporary.path().join("second-hook-ran");
    let state = State {
        oci_version: "1.3.0".to_string(),
        id: "demo".to_string(),
        status: ContainerStatus::Stopped,
        pid: Some(std::process::id() as i32),
        bundle: temporary.path().to_path_buf(),
        annotations: Some(HashMap::new()),
        ..State::default()
    };
    let failing = HookBuilder::default()
        .path("/bin/false")
        .args(vec!["false".to_string()])
        .build()
        .unwrap();
    let succeeding = HookBuilder::default()
        .path("/bin/sh")
        .args(vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("touch {}", marker.display()),
        ])
        .build()
        .unwrap();

    libcontainer::hooks::run_poststop_hooks(Some(&vec![failing, succeeding]), Some(&state));

    assert!(marker.exists());
}
