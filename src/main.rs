//! LibAFL fuzzer for Wayland compositors, driven via `wl_repeater`.
//!
//! # Architecture
//!
//! ```text
//!  LibAFL mutation engine
//!    └─► WlirInput  (parsed `.wlir` session in memory)
//!          └─► LibAFL harness closure
//!                └─► DifferentialExecutor::run()
//!                      ├─► replay target A via `wl_repeater`
//!                      ├─► replay target B via `wl_repeater`
//!                      └─► compare coarse replay outcomes
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
//! 2. Replay errors are still a coarse proxy for compositor crashes. They are
//!    useful for bring-up, but they still collapse multiple failure modes.
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

mod config;
mod differential;
mod wlir_input;
mod wlir_mutator;

use std::{fs, io, path::Path, process::ExitCode};

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus, Testcase},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    monitors::tui::TuiMonitor,
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::{HasCorpus, StdState},
};
use libafl_bolts::{rands::StdRand, tuples::tuple_list};
use wl_repeater::message::WaylandMessage;

use crate::{
    config::{load_runtime_config, parse_config_path},
    differential::{DifferentialExecutor, DifferentialOutcome},
    wlir_input::WlirInput,
    wlir_mutator::WlirMutator,
};

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

fn extract_coverage_pairs_from_messages(messages: &[WaylandMessage]) -> Vec<(u32, u16)> {
    messages
        .iter()
        .map(|message| (message.object_id, message.opcode))
        .collect()
}

fn eligible_coverage_pairs(outcome: &DifferentialOutcome, pairs: &[(u32, u16)]) -> Vec<(u32, u16)> {
    match outcome {
        DifferentialOutcome::SetupNoise => Vec::new(),
        DifferentialOutcome::EquivalentOk
        | DifferentialOutcome::EquivalentFailure
        | DifferentialOutcome::DivergentFailure { .. } => pairs.to_vec(),
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

fn map_differential_outcome_to_exit_kind(outcome: DifferentialOutcome) -> ExitKind {
    match outcome {
        DifferentialOutcome::DivergentFailure { .. } => ExitKind::Crash,
        DifferentialOutcome::EquivalentOk
        | DifferentialOutcome::EquivalentFailure
        | DifferentialOutcome::SetupNoise => ExitKind::Ok,
    }
}

fn ensure_crashes_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

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
    fn eligible_coverage_pairs_excludes_setup_noise_outcomes() {
        let pairs = vec![(7, 3)];
        assert!(eligible_coverage_pairs(&DifferentialOutcome::SetupNoise, &pairs).is_empty());
        assert_eq!(
            eligible_coverage_pairs(&DifferentialOutcome::EquivalentOk, &pairs),
            pairs
        );
        assert_eq!(
            eligible_coverage_pairs(
                &DifferentialOutcome::DivergentFailure {
                    left: "ok".to_owned(),
                    right: "disconnect_or_crash".to_owned(),
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
    fn divergent_failures_map_to_crash_exit_kind() {
        assert!(matches!(
            map_differential_outcome_to_exit_kind(DifferentialOutcome::DivergentFailure {
                left: "ok".to_owned(),
                right: "disconnect_or_crash".to_owned(),
            }),
            ExitKind::Crash
        ));
    }

    #[test]
    fn setup_noise_maps_to_ok_exit_kind() {
        assert!(matches!(
            map_differential_outcome_to_exit_kind(DifferentialOutcome::SetupNoise),
            ExitKind::Ok
        ));
    }

    #[test]
    fn ensure_crashes_dir_creates_missing_directory() {
        let temp = tempfile::tempdir().unwrap();
        let crashes = temp.path().join("crashes");

        ensure_crashes_dir(&crashes).unwrap();

        assert!(crashes.is_dir());
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
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let config_path = match parse_config_path(&args) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };

    let runtime_config = match load_runtime_config(&config_path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(err) = ensure_crashes_dir(&runtime_config.crashes_dir) {
        eprintln!("failed to create crashes dir: {err}");
        return ExitCode::FAILURE;
    }

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
        OnDiskCorpus::new(runtime_config.crashes_dir.clone()).unwrap(),
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
    // `InProcessExecutor` calls the differential harness in the same process as
    // the fuzzer, so executor crashes only prove the harness crashed.
    //
    // TODO(next): move replay behind compositor supervision / crash
    // classification, then switch this execution path to a subprocess or
    // forked model so the target process has an explicit containment boundary.
    //
    // `tuple_list!(observer)` hands the coverage observer to the executor so
    // it can flush and snapshot `SIGNALS` after every harness call before
    // `MaxMapFeedback` reads it.
    let differential = DifferentialExecutor::new(
        runtime_config.replay.clone(),
        runtime_config.targets.clone(),
    );
    let mut harness_fn = |input: &WlirInput| {
        let coverage_pairs = extract_coverage_pairs_from_messages(&input.messages);
        let outcome = differential.run(input);
        record_coverage_pairs(&eligible_coverage_pairs(&outcome, &coverage_pairs));
        map_differential_outcome_to_exit_kind(outcome)
    };
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
    if let Err(err) = install_startup_seeds(state.corpus_mut(), &runtime_config.corpus_dir) {
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
