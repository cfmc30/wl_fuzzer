#[path = "../src/config.rs"]
mod config;

#[path = "../src/differential.rs"]
mod differential;

#[path = "../src/wlir_input.rs"]
mod wlir_input;

use std::{env, io, path::PathBuf};

use config::{SharedReplayConfig, TargetConfig};
use differential::{
    classify_replay_result, compare_replay_outcomes, load_protocols, resolve_target_display_path,
    DifferentialOutcome, ReplayExecutor, ReplayOutcome,
};
use wl_repeater::ReplaySummary;
use wlir_input::WlirInput;

fn protocol_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("protocol")
}

fn minimal_wlir_with_message(object_id: u32, opcode: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x574C_4952u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&32u32.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&object_id.to_le_bytes());
    bytes.extend_from_slice(&opcode.to_le_bytes());
    bytes.push(0);
    bytes.push(0);
    bytes.extend_from_slice(&8u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&object_id.to_le_bytes());
    bytes.extend_from_slice(&opcode.to_le_bytes());
    bytes.extend_from_slice(&8u16.to_le_bytes());
    bytes
}

#[test]
fn ok_vs_disconnect_is_a_divergent_failure() {
    let outcome = compare_replay_outcomes(
        &ReplayOutcome::Ok,
        &ReplayOutcome::DisconnectedOrCrashed {
            reason: "peer disconnected".to_owned(),
        },
    );

    assert_eq!(
        outcome,
        DifferentialOutcome::DivergentFailure {
            left: "ok".to_owned(),
            right: "peer disconnected".to_owned(),
        }
    );
}

#[test]
fn symmetric_disconnects_are_not_objectives() {
    let outcome = compare_replay_outcomes(
        &ReplayOutcome::DisconnectedOrCrashed {
            reason: "broken pipe".to_owned(),
        },
        &ReplayOutcome::DisconnectedOrCrashed {
            reason: "connection reset".to_owned(),
        },
    );

    assert_eq!(outcome, DifferentialOutcome::EquivalentFailure);
}

#[test]
fn setup_failures_are_treated_as_non_objective_noise() {
    let outcome = compare_replay_outcomes(
        &ReplayOutcome::SetupFailed {
            reason: "missing runtime dir".to_owned(),
        },
        &ReplayOutcome::Ok,
    );

    assert_eq!(outcome, DifferentialOutcome::SetupNoise);
}

#[test]
fn relative_display_uses_target_runtime_dir_to_build_socket_path() {
    let target = TargetConfig {
        name: "left".to_owned(),
        xdg_runtime_dir: PathBuf::from("/tmp/runtime-a"),
        display: "wayland-0".to_owned(),
    };

    assert_eq!(
        resolve_target_display_path(&target),
        PathBuf::from("/tmp/runtime-a/wayland-0")
    );
}

#[test]
fn absolute_display_path_is_left_unchanged() {
    let target = TargetConfig {
        name: "left".to_owned(),
        xdg_runtime_dir: PathBuf::from("/tmp/runtime-a"),
        display: "/tmp/explicit-wayland.sock".to_owned(),
    };

    assert_eq!(
        resolve_target_display_path(&target),
        PathBuf::from("/tmp/explicit-wayland.sock")
    );
}

#[test]
fn classify_replay_result_treats_connection_reset_as_disconnect_or_crash() {
    let outcome = classify_replay_result(
        "left",
        Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "compositor closed connection",
        )),
    );

    assert!(matches!(
        outcome,
        ReplayOutcome::DisconnectedOrCrashed { reason }
            if reason.contains("left") && reason.contains("replay failed")
    ));
}

#[test]
fn classify_replay_result_treats_malformed_replay_data_as_setup_failed() {
    let invalid = classify_replay_result(
        "left",
        Err(io::Error::new(io::ErrorKind::InvalidData, "bad wlir")),
    );
    let truncated = classify_replay_result(
        "left",
        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated wlir",
        )),
    );

    assert!(matches!(invalid, ReplayOutcome::SetupFailed { reason } if reason.contains("left")));
    assert!(matches!(truncated, ReplayOutcome::SetupFailed { reason } if reason.contains("left")));
}

#[test]
fn load_protocols_reads_workspace_protocol_directory() {
    let protocol = load_protocols(&[protocol_dir()]).unwrap();
    assert!(protocol.interface("wl_display").is_some());
    assert!(protocol.interface("xdg_wm_base").is_some());
}

#[test]
fn load_protocols_ignores_nested_xml_files() {
    let temp = tempfile::tempdir().unwrap();
    let nested = temp.path().join("nested");
    std::fs::create_dir(&nested).unwrap();

    std::fs::write(
        temp.path().join("top.xml"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<protocol name="top">
  <interface name="top_iface" version="1">
    <request name="ping"/>
  </interface>
</protocol>
"#,
    )
    .unwrap();

    std::fs::write(
        nested.join("nested.xml"),
        r#"<?xml version="1.0" encoding="UTF-8"?>
<protocol name="nested">
  <interface name="nested_iface" version="1">
    <request name="ping"/>
  </interface>
</protocol>
"#,
    )
    .unwrap();

    let protocol = load_protocols(&[temp.path().to_path_buf()]).unwrap();
    assert!(protocol.interface("top_iface").is_some());
    assert!(protocol.interface("nested_iface").is_none());
}

#[test]
fn replay_executor_reports_missing_socket_as_setup_failed() {
    let temp = tempfile::tempdir().unwrap();
    let input = WlirInput::from_bytes(&minimal_wlir_with_message(1, 0)).unwrap();
    let executor = ReplayExecutor::new(
        SharedReplayConfig {
            protocol_dirs: vec![protocol_dir()],
            verbose: false,
            server_wait_timeout_ms: 100,
        },
        TargetConfig {
            name: "broken".to_owned(),
            xdg_runtime_dir: temp.path().to_path_buf(),
            display: temp
                .path()
                .join("missing-wayland.sock")
                .display()
                .to_string(),
        },
    );

    assert!(matches!(
        executor.run(&input),
        ReplayOutcome::SetupFailed { reason }
            if reason.contains("broken")
                && reason.contains("failed to build wl_repeater session")
    ));
}

#[test]
fn classify_replay_result_keeps_successful_replays_non_failing() {
    assert_eq!(
        classify_replay_result(
            "left",
            Ok(ReplaySummary {
                replayed: 1,
                drained: 0,
            }),
        ),
        ReplayOutcome::Ok
    );
}
