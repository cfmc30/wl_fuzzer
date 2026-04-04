#[path = "../src/config.rs"]
mod config;

use std::{fs, path::PathBuf};

use config::{load_runtime_config, load_runtime_config_from_str, parse_config_path};

fn valid_yaml() -> &'static str {
    r#"
corpus_dir: ./wl_fuzzer/corpus
crashes_dir: ./crashes
protocol_dirs:
  - ./protocol
verbose: false
server_wait_timeout_ms: 100
targets:
  - name: compositor_a
    xdg_runtime_dir: /run/user/1000
    display: wayland-0
  - name: compositor_b
    xdg_runtime_dir: /tmp/runtime-b
    display: wayland-1
"#
}

#[test]
fn parse_config_path_requires_explicit_config_flag() {
    let err = parse_config_path(&["wl_fuzzer".into()]).unwrap_err();
    assert!(err.contains("usage: wl_fuzzer --config <path>"));

    let parsed_with_different_argv0 = parse_config_path(&[
        "different_binary".into(),
        "--config".into(),
        "case.yaml".into(),
    ])
    .unwrap();
    assert_eq!(parsed_with_different_argv0, PathBuf::from("case.yaml"));

    let parsed =
        parse_config_path(&["wl_fuzzer".into(), "--config".into(), "case.yaml".into()]).unwrap();
    assert_eq!(parsed, PathBuf::from("case.yaml"));
}

#[test]
fn runtime_config_rejects_unknown_keys() {
    let err = load_runtime_config_from_str(
        r#"
corpus_dir: ./corpus
crashes_dir: ./crashes
protocol_dirs: [./protocol]
verbose: false
typo_verbose: true
targets:
  - name: compositor_a
    xdg_runtime_dir: /run/user/1000
    display: wayland-0
  - name: compositor_b
    xdg_runtime_dir: /tmp/runtime-b
    display: wayland-1
"#,
    )
    .unwrap_err();

    assert!(err.contains("unknown field"));
    assert!(err.contains("typo_verbose"));
}

#[test]
fn runtime_config_requires_exactly_two_targets() {
    let err = load_runtime_config_from_str(
        r#"
corpus_dir: ./corpus
crashes_dir: ./crashes
protocol_dirs: [./protocol]
verbose: false
server_wait_timeout_ms: 100
targets:
  - name: only_one
    xdg_runtime_dir: /run/user/1000
    display: wayland-0
"#,
    )
    .unwrap_err();

    assert!(err.contains("exactly two targets"));
}

#[test]
fn runtime_config_requires_per_target_runtime_dir() {
    let err = load_runtime_config_from_str(
        r#"
corpus_dir: ./corpus
crashes_dir: ./crashes
protocol_dirs: [./protocol]
verbose: false
server_wait_timeout_ms: 100
targets:
  - name: compositor_a
    xdg_runtime_dir: ""
    display: wayland-0
  - name: compositor_b
    xdg_runtime_dir: /tmp/runtime-b
    display: wayland-1
"#,
    )
    .unwrap_err();

    assert!(err.contains("targets[0].xdg_runtime_dir must not be empty"));
}

#[test]
fn runtime_config_requires_non_empty_corpus_dir() {
    let err = load_runtime_config_from_str(
        r#"
corpus_dir: ""
crashes_dir: ./crashes
protocol_dirs: [./protocol]
verbose: false
server_wait_timeout_ms: 100
targets:
  - name: compositor_a
    xdg_runtime_dir: /run/user/1000
    display: wayland-0
  - name: compositor_b
    xdg_runtime_dir: /tmp/runtime-b
    display: wayland-1
"#,
    )
    .unwrap_err();

    assert!(err.contains("corpus_dir must not be empty"));
}

#[test]
fn runtime_config_requires_non_empty_crashes_dir() {
    let err = load_runtime_config_from_str(
        r#"
corpus_dir: ./corpus
crashes_dir: ""
protocol_dirs: [./protocol]
verbose: false
server_wait_timeout_ms: 100
targets:
  - name: compositor_a
    xdg_runtime_dir: /run/user/1000
    display: wayland-0
  - name: compositor_b
    xdg_runtime_dir: /tmp/runtime-b
    display: wayland-1
"#,
    )
    .unwrap_err();

    assert!(err.contains("crashes_dir must not be empty"));
}

#[test]
fn runtime_config_requires_non_empty_protocol_dir_entries() {
    let err = load_runtime_config_from_str(
        r#"
corpus_dir: ./corpus
crashes_dir: ./crashes
protocol_dirs: [""]
verbose: false
server_wait_timeout_ms: 100
targets:
  - name: compositor_a
    xdg_runtime_dir: /run/user/1000
    display: wayland-0
  - name: compositor_b
    xdg_runtime_dir: /tmp/runtime-b
    display: wayland-1
"#,
    )
    .unwrap_err();

    assert!(err.contains("protocol_dirs[0] must not be empty"));
}

#[test]
fn runtime_config_parses_two_targets_and_shared_replay_settings() {
    let parsed = load_runtime_config_from_str(valid_yaml()).unwrap();

    assert_eq!(parsed.corpus_dir, PathBuf::from("./wl_fuzzer/corpus"));
    assert_eq!(parsed.crashes_dir, PathBuf::from("./crashes"));
    assert_eq!(
        parsed.replay.protocol_dirs,
        vec![PathBuf::from("./protocol")]
    );
    assert!(!parsed.replay.verbose);
    assert_eq!(parsed.replay.server_wait_timeout_ms, 100);
    assert_eq!(parsed.targets[0].name, "compositor_a");
    assert_eq!(
        parsed.targets[0].xdg_runtime_dir,
        PathBuf::from("/run/user/1000")
    );
    assert_eq!(parsed.targets[1].display, "wayland-1");
}

#[test]
fn load_runtime_config_resolves_relative_paths_against_config_directory() {
    let temp = tempfile::tempdir().unwrap();
    let config_dir = temp.path().join("configs").join("nested");
    fs::create_dir_all(&config_dir).unwrap();

    let config_path = config_dir.join("runtime.yaml");
    fs::write(
        &config_path,
        r#"
corpus_dir: ./corpus
crashes_dir: ./crashes
protocol_dirs:
  - ./protocol
verbose: false
server_wait_timeout_ms: 100
targets:
  - name: compositor_a
    xdg_runtime_dir: ./runtime-a
    display: wayland-0
  - name: compositor_b
    xdg_runtime_dir: ./runtime-b
    display: wayland-1
"#,
    )
    .unwrap();

    let parsed = load_runtime_config(&config_path).unwrap();

    assert_eq!(parsed.corpus_dir, config_dir.join("corpus"));
    assert_eq!(parsed.crashes_dir, config_dir.join("crashes"));
    assert_eq!(
        parsed.replay.protocol_dirs,
        vec![config_dir.join("protocol")]
    );
    assert_eq!(
        parsed.targets[0].xdg_runtime_dir,
        config_dir.join("runtime-a")
    );
    assert_eq!(
        parsed.targets[1].xdg_runtime_dir,
        config_dir.join("runtime-b")
    );
}
