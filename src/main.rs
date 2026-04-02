//! LibAFL fuzzer for Wayland compositors, driven via `wl_repeater`.
//!
//! # Architecture
//!
//! ```text
//!  LibAFL mutation engine
//!    └─► WlirInput  (parsed `.wlir` session in memory)
//!          └─► harness()
//!                └─► WlRepeaterFuzzer::fuzz_session()
//!                      ├─► local protocol loader for Wayland XML descriptors
//!                      ├─► wl_repeater::repeater::Repeater::new(&display, …)
//!                      └─► Repeater::run_from_messages(messages)
//!                │
//!                └─► SIGNALS coverage map   (temporary WLIR message-pair heuristic)
//!                      └─► StdMapObserver
//!                            ├─► MaxMapFeedback  (corpus novelty)
//!                            └─► CrashFeedback   (objective / saved to disk)
//! ```
//!
//! # Current Boundaries
//!
//! This integration now replays complete `.wlir` recordings through
//! `wl_repeater`, loads protocol XML locally, and seeds only from `./corpus/`,
//! but several boundaries are still explicit:
//!
//! 1. `InProcessExecutor` only protects the LibAFL harness itself. If the
//!    compositor misbehaves without taking the harness down, the executor does
//!    not classify that failure directly.
//! 2. Replay errors are still an imperfect proxy for compositor crashes. They
//!    are useful for bring-up, but they conflate compositor exits,
//!    disconnects, and other replay-time failures.
//! 3. Coverage still comes from the local `SIGNALS` map populated from parsed
//!    WLIR message pairs, not from compositor-side instrumentation.
//! 4. The harness should eventually move to subprocess or forked execution so
//!    crash containment and restart behavior are handled outside the current
//!    in-process boundary.
//!
//! # Next Milestones
//!
//! 1. **Next:** compositor supervision and crash classification, so replay can
//!    distinguish malformed inputs from real compositor exits or hangs.
//! 2. **After that:** shared-memory coverage from an instrumented compositor,
//!    replacing the local `SIGNALS` heuristic with target-side coverage.
//!
//! # Explicit Deferred Boundaries (`TODO(boundary)`)
//!
//! - argument-aware mutation
//! - protocol-aware message synthesis
//! - connection reuse / repeater reset
//! - replay duration and message-count caps
//! - smarter ownership to avoid cloning large message vectors

extern crate libafl;
extern crate libafl_bolts;

mod wlir_input;
mod wlir_mutator;

use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
    process::ExitCode,
};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    executors::{ExitKind, inprocess::InProcessExecutor},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    monitors::tui::TuiMonitor,
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list};
use wl_repeater::{ReplaySummary, message::WaylandMessage, protocol::Protocol, repeater::Repeater};

use crate::{wlir_input::WlirInput, wlir_mutator::WlirMutator};

// ── Coverage signal map ───────────────────────────────────────────────────────

/// Number of buckets in the in-process coverage signal map.
///
/// Sized to cover common Wayland object-id × opcode combinations without
/// excessive collision for typical sessions (object IDs rarely exceed a few
/// hundred; opcodes are small per-interface integers).
///
/// Replace this with the shared-memory map size exported by an instrumented
/// compositor once the local `SIGNALS` heuristic is retired in the later
/// coverage milestone.
const SIGNALS_LEN: usize = 1024;

/// Global byte-width coverage map updated by the harness on every iteration.
///
/// Each bucket is incremented (saturating) each time the harness observes a
/// Wayland wire message whose `(object_id, opcode)` pair hashes to that bucket.
/// `StdMapObserver` snapshots this map after each harness call to determine
/// whether an input produced novel coverage.
///
/// # Safety
///
/// LibAFL's `InProcessExecutor` calls the harness function single-threaded.
/// No concurrent writes to `SIGNALS` can occur, so unsynchronised mutation is
/// safe here.
static mut SIGNALS: [u8; SIGNALS_LEN] = [0u8; SIGNALS_LEN];

// ── WlRepeaterFuzzer ─────────────────────────────────────────────────────────

/// Configuration for one `WlRepeaterFuzzer` session.
///
/// Field names and types mirror the parameters accepted by
/// `wl_repeater::repeater::Repeater::new`.
pub struct WlRepeaterConfig {
    /// Name or absolute path of the Wayland display socket to target.
    ///
    /// A bare name (e.g. `"wayland-0"`) is resolved relative to
    /// `$XDG_RUNTIME_DIR` by `wl_repeater::conn::WaylandConn::connect`.
    pub display: String,

    /// Directories searched for Wayland XML protocol definition files.
    ///
    /// These are loaded by the local protocol discovery helper before replay.
    /// The default is the current working directory's `protocol/` entry, which
    /// matches the repository root in the usual workspace invocation.
    pub protocol_dirs: Vec<PathBuf>,

    /// Emit verbose per-message replay output.
    ///
    /// Mapped to the `verbose` parameter of `Repeater::new`.  Disable in
    /// production fuzzing runs to avoid I/O bottlenecks.
    pub verbose: bool,

    /// Per-message server-wait timeout (milliseconds).
    ///
    /// Forwarded to `Repeater::new` as `server_wait_timeout_ms`.  Short
    /// values reduce iteration latency; increase them for slow compositors.
    pub server_wait_timeout_ms: u64,
}

impl Default for WlRepeaterConfig {
    fn default() -> Self {
        WlRepeaterConfig {
            display: "wayland-0".to_owned(),
            protocol_dirs: vec![PathBuf::from("protocol")],
            verbose: false,
            server_wait_timeout_ms: 100,
        }
    }
}

/// Outcome of one `WlRepeaterFuzzer` session.
pub enum FuzzOutcome {
    /// Session completed without a replay-time failure.
    Ok,

    /// Replay/runtime failure bucket currently treated as a crash objective.
    ///
    /// This is the current in-process crash proxy for non-parse
    /// `Repeater::run` failures. It may reflect a real compositor crash or
    /// hang, but it can also include other replay-time failures until explicit
    /// compositor supervision/classification lands.
    ///
    /// `harness` maps this to `ExitKind::Crash` so LibAFL saves the input in
    /// the on-disk crash corpus for later triage.
    Crash { reason: String },

    /// Non-crash rejection bucket for inputs or setup that cannot be replayed.
    ///
    /// This includes malformed mutated `.wlir` inputs as well as environmental
    /// setup problems such as missing sockets or protocol-load failures.
    /// `harness` maps it to `ExitKind::Ok`, so the input is not kept in the
    /// crash corpus.
    SetupFailed { reason: String },
}

/// Wrapper around `wl_repeater::repeater::Repeater` for use inside a LibAFL
/// in-process harness.
///
/// The fuzzer input model is `WlirInput` (`header + messages`). `fuzz_session`
/// replays `input.messages` via `Repeater::run_from_messages`, then classifies
/// replay results into `FuzzOutcome` values for LibAFL.
pub struct WlRepeaterFuzzer {
    config: WlRepeaterConfig,
}

impl WlRepeaterFuzzer {
    /// Create a fuzzer from the given configuration.
    pub fn new(config: WlRepeaterConfig) -> Self {
        WlRepeaterFuzzer { config }
    }

    /// Run one fuzzing session with `input` as a structured WLIR session.
    ///
    /// Malformed `.wlir` persistence bytes are expected during mutation and
    /// parse/interop failures map to `FuzzOutcome::SetupFailed` rather than `Crash`.

    pub fn fuzz_session(&self, input: &WlirInput) -> FuzzOutcome {
        let coverage_pairs = extract_coverage_pairs_from_messages(&input.messages);

        let mut repeater = match build_repeater(&self.config, input.header.start_time_us) {
            Ok(repeater) => repeater,
            Err(err) => {
                return FuzzOutcome::SetupFailed {
                    reason: format!("failed to build wl_repeater session: {err}"),
                };
            }
        };

        let outcome = classify_replay_result(repeater.run_from_messages(input.messages.clone()));
        record_coverage_pairs(&eligible_coverage_pairs(&outcome, &coverage_pairs));
        outcome
    }
}

fn build_repeater(config: &WlRepeaterConfig, start_time_us: u64) -> io::Result<Repeater> {
    let protocol = load_protocols(&config.protocol_dirs)
        .map_err(|err| io::Error::other(format!("failed to load protocols: {err}")))?;

    Repeater::new(
        &config.display,
        config.verbose,
        false,
        false,
        config.server_wait_timeout_ms,
        start_time_us,
        protocol,
    )
}

fn classify_replay_result(result: io::Result<ReplaySummary>) -> FuzzOutcome {
    // TODO(boundary): replay errors are only a rough crash proxy right now.
    // The next milestone adds compositor supervision and crash classification
    // so this mapping can separate compositor exits/hangs from replay-layer
    // failures that do not represent a target crash.
    match result {
        Ok(_) => FuzzOutcome::Ok,
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
            ) =>
        {
            FuzzOutcome::SetupFailed {
                reason: format!("replay rejected malformed .wlir input: {err}"),
            }
        }
        Err(err) => FuzzOutcome::Crash {
            reason: format!("replay failed: {err}"),
        },
    }
}

fn extract_coverage_pairs_from_messages(messages: &[WaylandMessage]) -> Vec<(u32, u16)> {
    messages
        .iter()
        .map(|message| (message.object_id, message.opcode))
        .collect()
}

fn eligible_coverage_pairs(outcome: &FuzzOutcome, pairs: &[(u32, u16)]) -> Vec<(u32, u16)> {
    match outcome {
        FuzzOutcome::SetupFailed { .. } => Vec::new(),
        FuzzOutcome::Ok | FuzzOutcome::Crash { .. } => pairs.to_vec(),
    }
}

fn record_coverage_pairs(pairs: &[(u32, u16)]) {
    for (object_id, opcode) in pairs {
        let bucket = coverage_bucket(*object_id, *opcode);
        // SAFETY: LibAFL in-process executor is single-threaded; no
        // concurrent mutations of SIGNALS occur.
        unsafe {
            SIGNALS[bucket] = SIGNALS[bucket].saturating_add(1);
        }
    }
}

// ── Temporary coverage helpers ───────────────────────────────────────────────

/// Extract `(object_id, opcode)` pairs from parsed WLIR message records.
///
/// This remains a temporary in-process coverage source, but it is WLIR-aware:
/// coverage comes from successful `IrReader::next_message()` decoding rather
/// than raw container bytes.

/// Map a `(object_id, opcode)` pair to a `SIGNALS` bucket index.
///
/// Uses a multiplicative Fibonacci hash so common low-numbered Wayland objects
/// (`wl_display = 1`, `wl_registry = 2`, …) and small opcode values spread
/// across the full bucket space rather than clustering at low indices.
fn coverage_bucket(object_id: u32, opcode: u16) -> usize {
    // Knuth multiplicative hash constant (2^32 / golden ratio).
    let h = (object_id as usize)
        .wrapping_mul(0x9e37_79b9)
        .wrapping_add(opcode as usize);
    h % SIGNALS_LEN
}

/// Load seed recordings from a directory containing `.wlir` files.
pub(crate) fn load_seed_recordings(dir: &Path) -> io::Result<Vec<WlirInput>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut seeds = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("wlir") {
            continue;
        }
        let bytes = fs::read(&path)?;
        if !bytes.is_empty() {
            seeds.push(WlirInput::from_bytes(&bytes).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse seed {}: {err}", path.display()),
                )
            })?);
        }
    }

    Ok(seeds)
}

pub(crate) fn default_corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus")
}

/// Select the explicit startup seeds for the initial corpus.
///
/// Startup requires real `.wlir` recordings from `corpus/`. If that directory
/// has no usable `.wlir` entries, startup fails before the fuzz loop begins.
pub(crate) fn select_startup_seeds(corpus_dir: &Path) -> io::Result<Vec<WlirInput>> {
    let seeds = load_seed_recordings(corpus_dir)?;
    if !seeds.is_empty() {
        return Ok(seeds);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("startup seed corpus is empty: {}", corpus_dir.display()),
    ))
}

pub(crate) fn install_startup_seeds<C>(corpus: &mut C, corpus_dir: &Path) -> io::Result<()>
where
    C: Corpus<WlirInput>,
{
    for seed in select_startup_seeds(corpus_dir)? {
        corpus.add(Testcase::new(seed)).map_err(|err| {
            io::Error::other(format!("failed to add startup seed to corpus: {err}"))
        })?;
    }

    Ok(())
}

/// Load Wayland protocol XML files into a single registry.
///
/// This initial implementation lives in `wl_fuzzer` so the compositor replay
/// path can start using protocol loading without waiting on a shared helper.
/// If `wl_repeater/src/main.rs` also needs the same traversal logic, move the
/// helper into `wl_repeater::protocol` and call it from both crates.
#[allow(dead_code)]
fn load_protocols(paths: &[PathBuf]) -> Result<Protocol, Box<dyn Error>> {
    let mut xml_files = Vec::new();

    for path in paths {
        collect_protocol_xml_files(path, &mut xml_files)?;
    }

    xml_files.sort();

    let mut protocol = Protocol::new();
    for xml_file in xml_files {
        protocol.load_file(&xml_file)?;
    }

    Ok(protocol)
}

#[allow(dead_code)]
fn collect_protocol_xml_files(
    path: &Path,
    xml_files: &mut Vec<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    let metadata = fs::metadata(path)?;

    if metadata.is_dir() {
        let mut entries = fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()?;
        entries.sort();

        for entry in entries {
            if entry.extension().and_then(|ext| ext.to_str()) == Some("xml") {
                xml_files.push(entry);
            }
        }
        return Ok(());
    }

    if path.extension().and_then(|ext| ext.to_str()) == Some("xml") {
        xml_files.push(path.to_path_buf());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

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
    fn extract_coverage_pairs_from_messages_reads_message_records() {
        let input = WlirInput::from_bytes(&minimal_wlir_with_message(7, 3)).unwrap();
        let parsed = extract_coverage_pairs_from_messages(&input.messages);
        assert_eq!(parsed, vec![(7, 3)]);
    }

    #[test]
    fn eligible_coverage_pairs_excludes_setup_failed_outcomes() {
        let pairs = vec![(7, 3)];
        assert!(
            eligible_coverage_pairs(
                &FuzzOutcome::SetupFailed {
                    reason: "bad input".to_owned(),
                },
                &pairs
            )
            .is_empty()
        );
        assert_eq!(eligible_coverage_pairs(&FuzzOutcome::Ok, &pairs), pairs);
        assert_eq!(
            eligible_coverage_pairs(
                &FuzzOutcome::Crash {
                    reason: "boom".to_owned(),
                },
                &pairs,
            ),
            pairs
        );
    }

    #[test]
    fn wlir_input_rejects_non_wlir_bytes() {
        let err = WlirInput::from_bytes(b"not-wlir").unwrap_err();
        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof
        ));
    }

    #[test]
    fn wlir_input_accepts_valid_wlir_header() {
        let mut bytes = vec![0u8; 24];
        bytes[0..4].copy_from_slice(&0x574C_4952u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&1234u64.to_le_bytes());

        let input = WlirInput::from_bytes(&bytes).unwrap();
        assert_eq!(input.header.start_time_us, 1234);
    }

    #[test]
    fn build_repeater_surfaces_socket_connection_failures() {
        let protocol_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("protocol");
        let config = WlRepeaterConfig {
            display: tempfile::tempdir()
                .unwrap()
                .path()
                .join("missing-wayland.sock")
                .display()
                .to_string(),
            protocol_dirs: vec![protocol_dir],
            verbose: false,
            server_wait_timeout_ms: 500,
        };

        let err = match build_repeater(&config, 77) {
            Ok(_) => panic!("expected socket connection failure"),
            Err(err) => err,
        };
        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::NotFound
                | std::io::ErrorKind::PermissionDenied
                | std::io::ErrorKind::ConnectionRefused
        ));
    }

    #[test]
    fn classify_replay_result_returns_ok_on_success() {
        assert!(matches!(
            classify_replay_result(Ok(ReplaySummary {
                replayed: 0,
                drained: 0
            })),
            FuzzOutcome::Ok
        ));
    }

    #[test]
    fn classify_replay_result_treats_replay_errors_as_crashes() {
        let outcome = classify_replay_result(Err(std::io::Error::other("boom")));
        assert!(matches!(outcome, FuzzOutcome::Crash { .. }));
    }

    #[test]
    fn classify_replay_result_treats_reader_parse_errors_as_setup_failures() {
        let outcome = classify_replay_result(Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated record",
        )));
        assert!(matches!(outcome, FuzzOutcome::SetupFailed { .. }));
    }

    #[test]
    fn load_seed_recordings_reads_only_wlir_files() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("a.wlir"), minimal_wlir_with_message(1, 0)).unwrap();
        fs::write(tmp.path().join("note.txt"), b"skip").unwrap();

        let seeds = load_seed_recordings(tmp.path()).unwrap();
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].messages.len(), 1);
    }

    #[test]
    fn load_seed_recordings_handles_missing_dir() {
        let missing = Path::new("definitely-missing-corpus-dir");
        let seeds = load_seed_recordings(missing).unwrap();
        assert!(seeds.is_empty());
    }

    #[test]
    fn load_seed_recordings_surfaces_io_error_for_bad_wlir_entry() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("bad.wlir")).unwrap();

        let err = load_seed_recordings(tmp.path()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::IsADirectory);
    }

    #[test]
    fn load_protocols_from_directory_loads_xml_files() {
        let protocol_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("protocol");

        let protocol = load_protocols(&[protocol_dir]).unwrap();
        assert!(protocol.interface("wl_display").is_some());
        assert!(protocol.interface("xdg_wm_base").is_some());
    }

    #[test]
    fn load_protocols_from_single_xml_path_loads_that_file() {
        let protocol_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("protocol")
            .join("wayland.xml");

        let protocol = load_protocols(&[protocol_path]).unwrap();
        assert!(protocol.interface("wl_display").is_some());
        assert!(protocol.interface("xdg_wm_base").is_none());
    }

    #[test]
    fn load_protocols_from_directory_ignores_nested_xml_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let nested = root.join("nested");
        fs::create_dir(&nested).unwrap();

        fs::write(
            root.join("top.xml"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<protocol name="top">
  <interface name="top_iface" version="1">
    <request name="ping"/>
  </interface>
</protocol>
"#,
        )
        .unwrap();

        fs::write(
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

        let protocol = load_protocols(&[root.to_path_buf()]).unwrap();
        assert!(protocol.interface("top_iface").is_some());
        assert!(protocol.interface("nested_iface").is_none());
    }
}

// ── LibAFL in-process harness ─────────────────────────────────────────────────

/// LibAFL in-process harness function.
///
/// One call to `harness` constitutes one complete fuzzing iteration:
///
/// 1. Interprets `input` as a structured `WlirInput` session.
/// 2. Forwards it to `WlRepeaterFuzzer::fuzz_session`, which replays
///    pre-parsed messages through `wl_repeater`.
/// 3. Maps `FuzzOutcome` to a `ExitKind` for LibAFL:
///    - `Ok`          → `ExitKind::Ok`
///    - `Crash`       → `ExitKind::Crash`   (input saved to crash corpus)
///    - `SetupFailed` → `ExitKind::Ok`      (non-crash rejection: malformed
///                                           WLIR or replay setup failure)
///
/// # Note on per-call allocation
///
/// `WlRepeaterFuzzer` is constructed fresh on every call. This is acceptable
/// for the current boundary-marking milestone, but the harness should
/// eventually move to subprocess or forked execution once compositor
/// supervision and restart logic exist.
fn harness(input: &WlirInput) -> ExitKind {
    // TODO(boundary): `InProcessExecutor` only isolates the harness. It does
    // not supervise or restart the compositor, so this in-process harness is a
    // temporary execution model until the replay path moves behind a
    // subprocess/forked boundary.
    let fuzzer = WlRepeaterFuzzer::new(WlRepeaterConfig::default());

    match fuzzer.fuzz_session(input) {
        FuzzOutcome::Ok => ExitKind::Ok,
        FuzzOutcome::Crash { .. } => ExitKind::Crash,
        FuzzOutcome::SetupFailed { .. } => ExitKind::Ok,
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    // ── Monitor ───────────────────────────────────────────────────────────────
    //
    // Prints fuzzer statistics (executions/s, corpus size, crashes) to stdout.
    //     let mon = SimpleMonitor::new(|s| println!("{s}"));

    let mon = TuiMonitor::builder()
        .title("Wayland Fuzzer")
        .enhanced_graphics(false)
        .build();

    // ── Event manager ─────────────────────────────────────────────────────────
    //
    // Handles events produced during the fuzzing loop (e.g. new corpus entry
    // found, crash detected).  The `Simple` variant runs everything in-process
    // with no IPC; replace with `LlmpRestartingEventManager` for multi-process
    // or distributed campaigns.
    let mut mgr = SimpleEventManager::new(mon);

    // ── Corpus scheduler ──────────────────────────────────────────────────────
    //
    // `QueueScheduler` replays test cases in FIFO order — deterministic and
    // easy to reason about during early harness development.  Switch to
    // `WeightedScheduler` or `MinimizerScheduler` once the corpus grows.
    let scheduler = QueueScheduler::new();

    // ── Coverage observer ─────────────────────────────────────────────────────
    //
    // `StdMapObserver` wraps the global `SIGNALS` byte array and produces a
    // snapshot of it after every harness call. `MaxMapFeedback` still uses
    // this local in-process map for novelty; it is not real compositor code
    // coverage yet.
    //
    // TODO(next+1): replace `SIGNALS` with a shared-memory coverage map owned
    // by an instrumented compositor binary.
    //
    // SAFETY: `SIGNALS` is only mutated inside `harness`, and LibAFL's
    // `InProcessExecutor` calls `harness` single-threaded.  `&raw mut SIGNALS`
    // produces a raw pointer that is not dereferenced until the fuzzing loop
    // runs, at which point no aliasing mutation can occur.
    let observer = unsafe { StdMapObserver::new("signals", &mut *(&raw mut SIGNALS)) };

    // ── Feedback and objective ────────────────────────────────────────────────
    //
    // `MaxMapFeedback` marks an input as *interesting* (and adds it to the
    // evolving corpus) whenever it raises at least one byte in the `SIGNALS`
    // map above its historical maximum — i.e. it reaches a new
    // (object_id × opcode) pair not seen before.
    //
    // `CrashFeedback` marks an input as an *objective* (saved to the on-disk
    // crash corpus) when the harness returns `ExitKind::Crash`.
    let mut feedback = MaxMapFeedback::new(&observer);
    let mut objective = CrashFeedback::new();

    // ── State ─────────────────────────────────────────────────────────────────
    //
    // `StdState` bundles the RNG, the evolving in-memory corpus, and the
    // on-disk crash corpus.  `StdState::new` calls `feedback.init_state` and
    // `objective.init_state` internally, which is why mutable references are
    // required here even though ownership is later transferred to `StdFuzzer`.
    let mut state = StdState::new(
        StdRand::new(),
        // Evolving corpus: kept in memory for maximum throughput.
        InMemoryCorpus::<WlirInput>::new(),
        // Crash corpus: written to disk so inputs survive a fuzzer restart.
        OnDiskCorpus::new(PathBuf::from("./crashes")).unwrap(),
        &mut feedback,
        &mut objective,
    )
    .expect("failed to create fuzzer state");

    // ── Fuzzer ────────────────────────────────────────────────────────────────
    //
    // `StdFuzzer` ties together the corpus scheduler, the coverage feedback,
    // and the crash objective into the main fuzzing driver.
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // ── Executor ──────────────────────────────────────────────────────────────
    //
    // `InProcessExecutor` calls `harness` in the same process as the fuzzer,
    // so executor crashes only prove the harness crashed. Compositor failures
    // are still inferred indirectly from replay-result classification.
    //
    // TODO(next): move replay behind compositor supervision / crash
    // classification, then switch this execution path to a subprocess or
    // forked model so the target process has an explicit containment boundary.
    //
    // `tuple_list!(observer)` hands the coverage observer to the executor so
    // it can flush and snapshot `SIGNALS` after every harness call before
    // `MaxMapFeedback` reads it.
    let mut harness_fn = harness;
    let mut executor = InProcessExecutor::new(
        &mut harness_fn,
        tuple_list!(observer),
        &mut fuzzer,
        &mut state,
        &mut mgr,
    )
    .expect("failed to create InProcessExecutor");

    // ── Initial corpus ────────────────────────────────────────────────────────
    //
    let corpus_dir = default_corpus_dir();
    if let Err(err) = install_startup_seeds(state.corpus_mut(), &corpus_dir) {
        eprintln!("failed to initialize startup seeds: {err}");
        return ExitCode::FAILURE;
    }

    // ── Mutation stage ────────────────────────────────────────────────────────
    //
    // `WlirMutator` performs first-pass structural-safe message mutations
    // (remove, duplicate, swap-adjacent, bounded timestamp/object/opcode edits)
    // while preserving payload semantics for `wire_data[8..]` and FD content.
    //
    // TODO(later): add protocol-semantic argument-aware mutations once message
    // decoding/validation hooks are integrated into the mutator.
    let mutator = WlirMutator;
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));
    // let mut stages = tuple_list!();
    // let mut stages = ();

    // ── Fuzzing loop ──────────────────────────────────────────────────────────
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("error in the fuzzing loop");

    ExitCode::SUCCESS
}
