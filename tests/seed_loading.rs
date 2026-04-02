#[path = "../src/wlir_input.rs"]
mod wlir_input;

#[path = "../src/wlir_mutator.rs"]
mod wlir_mutator;

#[path = "../src/main.rs"]
#[allow(dead_code)]
mod main_impl;

use std::{fs, path::PathBuf};

use libafl::corpus::{Corpus, InMemoryCorpus};
use main_impl::{
    FuzzOutcome, WlRepeaterConfig, WlRepeaterFuzzer, default_corpus_dir, install_startup_seeds,
    load_seed_recordings, select_startup_seeds,
};
use wlir_input::WlirInput;

fn protocol_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("protocol")
}

fn missing_display_socket() -> String {
    tempfile::tempdir()
        .unwrap()
        .path()
        .join("missing-wayland.sock")
        .display()
        .to_string()
}

fn temp_corpus_dir(root: &std::path::Path) -> PathBuf {
    root.join("corpus")
}

fn corrupt_wlir_with_unknown_record_smaller_than_header() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0x574C_4952u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    bytes.extend_from_slice(&99u32.to_le_bytes());
    bytes.extend_from_slice(&4u32.to_le_bytes());

    bytes
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
fn default_corpus_dir_points_at_repo_corpus_directory() {
    assert_eq!(
        default_corpus_dir(),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus")
    );
}

#[test]
fn load_seed_recordings_discovers_only_wlir_files_from_temp_corpus_directory() {
    let temp = tempfile::tempdir().unwrap();
    let corpus = temp_corpus_dir(temp.path());
    fs::create_dir(&corpus).unwrap();
    let fixture_bytes = minimal_wlir_with_message(1, 0);
    fs::write(corpus.join("seed.wlir"), &fixture_bytes).unwrap();
    fs::write(corpus.join("ignored.txt"), b"skip this file").unwrap();

    let seeds = load_seed_recordings(&corpus).unwrap();

    assert_eq!(seeds.len(), 1);
    assert_eq!(seeds[0].messages.len(), 1);
    assert_eq!(seeds[0].messages[0].object_id, 1);
    assert_eq!(seeds[0].messages[0].opcode, 0);
}

#[test]
fn select_startup_seeds_prefers_corpus_entries_when_present() {
    let temp = tempfile::tempdir().unwrap();
    let corpus = temp_corpus_dir(temp.path());
    fs::create_dir(&corpus).unwrap();

    let corpus_bytes = minimal_wlir_with_message(1, 0);
    fs::write(corpus.join("seed.wlir"), &corpus_bytes).unwrap();

    let selected = select_startup_seeds(&corpus).unwrap();

    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].messages.len(), 1);
    assert_eq!(selected[0].messages[0].object_id, 1);
    assert_eq!(selected[0].messages[0].opcode, 0);
}

#[test]
fn select_startup_seeds_errors_when_corpus_is_empty() {
    let temp = tempfile::tempdir().unwrap();
    let corpus = temp_corpus_dir(temp.path());
    fs::create_dir(&corpus).unwrap();

    let err = select_startup_seeds(&corpus).unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert!(err.to_string().contains("startup seed corpus is empty"));
}

#[test]
fn install_startup_seeds_returns_error_when_corpus_is_empty() {
    let temp = tempfile::tempdir().unwrap();
    let corpus_dir = temp_corpus_dir(temp.path());
    fs::create_dir(&corpus_dir).unwrap();
    let mut corpus = InMemoryCorpus::<WlirInput>::new();

    let err = install_startup_seeds(&mut corpus, &corpus_dir).unwrap_err();

    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(corpus.count(), 0);
}

#[test]
fn malformed_wlir_is_classified_as_non_crash_setup_failure() {
    let fuzzer = WlRepeaterFuzzer::new(WlRepeaterConfig {
        display: missing_display_socket(),
        protocol_dirs: vec![protocol_dir()],
        verbose: false,
        server_wait_timeout_ms: 500,
    });

    let bad = WlirInput {
        header: wl_repeater::ir::IrFileHeader {
            magic: 0x574C_4952,
            version: 2,
            start_time_us: 0,
            flags: 0,
            reserved: 0,
        },
        messages: Vec::new(),
    };

    assert!(matches!(
        fuzzer.fuzz_session(&bad),
        FuzzOutcome::SetupFailed { reason }
            if reason.contains("failed to build wl_repeater session")
    ));
}

#[test]
fn header_valid_corrupt_unknown_record_is_setup_failed_without_panicking() {
    let _fuzzer = WlRepeaterFuzzer::new(WlRepeaterConfig {
        display: missing_display_socket(),
        protocol_dirs: vec![protocol_dir()],
        verbose: false,
        server_wait_timeout_ms: 500,
    });
    let bytes = corrupt_wlir_with_unknown_record_smaller_than_header();
    let err = WlirInput::from_bytes(&bytes).unwrap_err();
    assert!(
        err.to_string()
            .contains("unknown record smaller than header")
    );
}

#[test]
fn generated_wlir_fixture_loads_as_known_good_input() {
    let bytes = minimal_wlir_with_message(1, 0);

    let input = WlirInput::from_bytes(&bytes).unwrap();
    assert_eq!(input.messages.len(), 1);
}

#[test]
fn missing_display_socket_is_reported_as_setup_failed() {
    let input = WlirInput::from_bytes(&minimal_wlir_with_message(1, 0)).unwrap();
    let fuzzer = WlRepeaterFuzzer::new(WlRepeaterConfig {
        display: missing_display_socket(),
        protocol_dirs: vec![protocol_dir()],
        verbose: false,
        server_wait_timeout_ms: 500,
    });

    assert!(matches!(
        fuzzer.fuzz_session(&input),
        FuzzOutcome::SetupFailed { reason }
            if reason.contains("failed to build wl_repeater session")
    ));
}
