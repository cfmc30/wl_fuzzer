//! LibAFL fuzzer for Wayland compositors, driven via `wl_repeater`.
//!
//! # Architecture
//!
//! ```text
//!  LibAFL mutation engine
//!    └─► BytesInput  (fuzzed Wayland wire bytes)
//!          └─► harness()
//!                └─► WlRepeaterFuzzer::fuzz_session()   ← placeholder stub
//!                      │
//!                      │  TODO (M3 – compositor harness):
//!                      ├─► wl_repeater::protocol::Protocol::load_from_dirs()
//!                      ├─► wl_repeater::repeater::Repeater::new(&display, …)
//!                      ├─► wl_repeater::ir::IrReader::from_bytes(wire_bytes)
//!                      └─► Repeater::run(&mut reader)
//!                │
//!                └─► SIGNALS coverage map   (object_id × opcode hash)
//!                      └─► StdMapObserver
//!                            ├─► MaxMapFeedback  (corpus novelty)
//!                            └─► CrashFeedback   (objective / saved to disk)
//! ```
//!
//! # Integration Plan
//!
//! The steps required to transition `WlRepeaterFuzzer` from a coverage stub to
//! a real compositor-driving harness are:
//!
//! 1. **`IrReader::from_bytes`** — add a constructor to
//!    `wl_repeater::ir::IrReader` that accepts raw bytes instead of a file
//!    path, so mutated wire streams can be fed in directly.
//!
//! 2. **Compositor harness (M3)** — spawn the target compositor under a
//!    supervisor that can detect abnormal exits (pid-file, socket-liveness
//!    probe, or SIGCHLD watcher) and restart it between sessions.
//!
//! 3. **`WlRepeaterFuzzer::fuzz_session`** — uncomment the `Repeater::run`
//!    block and map compositor-crash detection to `FuzzOutcome::Crash`.
//!
//! 4. **Seed corpus (M4)** — load real `.wlir` trace files from `./corpus/`
//!    as `BytesInput` seeds instead of the random printable generator used now.
//!
//! 5. **Coverage source (M5)** — replace the in-process `SIGNALS` map with a
//!    shared-memory map written by an instrumented compositor binary so
//!    `MaxMapFeedback` reflects genuine code-coverage novelty.

extern crate libafl;
extern crate libafl_bolts;

use std::path::PathBuf;

use libafl::{
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::SimpleEventManager,
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedbacks::{CrashFeedback, MaxMapFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    generators::RandPrintablesGenerator,
    inputs::{BytesInput, HasTargetBytes},
    monitors::SimpleMonitor,
    mutators::{havoc_mutations, scheduled::HavocScheduledMutator},
    observers::StdMapObserver,
    schedulers::QueueScheduler,
    stages::mutational::StdMutationalStage,
    state::StdState,
};
use libafl_bolts::{nonzero, rands::StdRand, tuples::tuple_list, AsSlice};

// ── Coverage signal map ───────────────────────────────────────────────────────

/// Number of buckets in the in-process coverage signal map.
///
/// Sized to cover common Wayland object-id × opcode combinations without
/// excessive collision for typical sessions (object IDs rarely exceed a few
/// hundred; opcodes are small per-interface integers).
///
/// When real compositor code-coverage is available (step 5 of the integration
/// plan), replace this with the actual shared-memory map size exported by the
/// instrumented compositor binary.
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

// ── WlRepeaterFuzzer placeholder ─────────────────────────────────────────────

/// Configuration for one `WlRepeaterFuzzer` session.
///
/// Field names and types mirror the parameters accepted by
/// `wl_repeater::repeater::Repeater::new` so the transition from the stub to
/// the real implementation is a direct substitution.
pub struct WlRepeaterConfig {
    /// Name or absolute path of the Wayland display socket to target.
    ///
    /// A bare name (e.g. `"wayland-0"`) is resolved relative to
    /// `$XDG_RUNTIME_DIR` by `wl_repeater::conn::WaylandConn::connect`.
    pub display: String,

    /// Directories searched for Wayland XML protocol definition files.
    ///
    /// Forwarded to `wl_repeater::protocol::Protocol` at load time.
    /// The default points at the `protocol/` tree in this repository.
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
            server_wait_timeout_ms: 500,
        }
    }
}

/// Outcome of one `WlRepeaterFuzzer` session.
pub enum FuzzOutcome {
    /// Session completed without a detected compositor crash.
    Ok,

    /// The compositor exited or disconnected unexpectedly during replay.
    ///
    /// `harness` maps this to `ExitKind::Crash` so LibAFL saves the input to
    /// the on-disk crash corpus.
    Crash { reason: String },

    /// Session could not be set up (socket missing, protocol load failure, …).
    ///
    /// Treated as a non-crash by `harness` so the input is discarded rather
    /// than saved; the underlying cause should be fixed before fuzzing.
    SetupFailed { reason: String },
}

/// Placeholder wrapper around `wl_repeater::repeater::Repeater` for use inside
/// a LibAFL in-process harness.
///
/// # Current state
///
/// `fuzz_session` parses the fuzzed bytes as Wayland wire message headers and
/// updates the in-process `SIGNALS` coverage map.  No compositor connection is
/// opened, so the fuzzer runs safely without a live Wayland session.
///
/// # Transition to real compositor fuzzing
///
/// Replace the stub body of `fuzz_session` with the block below once the
/// prerequisites listed in the integration plan are in place:
///
/// ```ignore
/// use wl_repeater::ir::IrReader;
/// use wl_repeater::protocol::Protocol;
/// use wl_repeater::repeater::Repeater;
///
/// // 1. Load Wayland protocol descriptors.
/// let protocol = Protocol::load_from_dirs(&self.config.protocol_dirs)
///     .map_err(|e| FuzzOutcome::SetupFailed { reason: e.to_string() })?;
///
/// // 2. Open a connection to the live compositor.
/// let mut repeater = Repeater::new(
///     &self.config.display,
///     self.config.verbose,
///     /*timed=*/           false,
///     /*wait=*/            false,
///     /*no_wait_server=*/  false,
///     self.config.server_wait_timeout_ms,
///     /*start_us=*/        0,
///     protocol,
/// )
/// .map_err(|e| FuzzOutcome::SetupFailed { reason: e.to_string() })?;
///
/// // 3. Wrap the fuzzed bytes in an IrReader.
/// //    Prerequisite: add IrReader::from_bytes(data: &[u8]) to wl_repeater::ir.
/// let mut reader = IrReader::from_bytes(wire_bytes)
///     .map_err(|e| return FuzzOutcome::SetupFailed { reason: e.to_string() })?;
///
/// // 4. Replay the session; a broken-pipe or protocol error indicates a crash.
/// if let Err(e) = repeater.run(&mut reader) {
///     return FuzzOutcome::Crash { reason: e.to_string() };
/// }
///
/// // 5. External compositor health check.
/// //    Prerequisite: implement compositor_is_alive() using a pid-file or
/// //    socket-liveness probe maintained by the compositor harness.
/// if !compositor_is_alive() {
///     return FuzzOutcome::Crash {
///         reason: "compositor exited unexpectedly".to_owned(),
///     };
/// }
/// ```
pub struct WlRepeaterFuzzer {
    // The config field is intentionally dormant until the real Repeater::run
    // integration lands in M3.  Suppress the dead_code lint so the placeholder
    // compiles cleanly without noise.
    #[allow(dead_code)]
    config: WlRepeaterConfig,
    // TODO(M3): hold a pre-loaded Protocol so XML files are not re-parsed
    // on every harness call.
    //
    //     protocol: wl_repeater::protocol::Protocol,
}

impl WlRepeaterFuzzer {
    /// Create a fuzzer from the given configuration.
    ///
    /// When compositor integration is added, this constructor should also load
    /// the protocol XML files via `wl_repeater::protocol::Protocol` and verify
    /// that the compositor socket is reachable before returning.
    pub fn new(config: WlRepeaterConfig) -> Self {
        // TODO(M3): load and cache Protocol here:
        //
        //     let protocol =
        //         wl_repeater::protocol::Protocol::load_from_dirs(&config.protocol_dirs)
        //             .expect("failed to load Wayland protocol XML");

        WlRepeaterFuzzer {
            config,
            // protocol,
        }
    }

    /// Run one fuzzing session with `wire_bytes` as the Wayland message stream.
    ///
    /// `wire_bytes` are treated as a flat sequence of Wayland wire messages.
    /// Each message begins with an 8-byte header:
    ///
    /// ```text
    /// Bytes 0–3 : object_id  (u32 little-endian)
    /// Bytes 4–5 : opcode     (u16 little-endian)
    /// Bytes 6–7 : size       (u16 little-endian, total message length in bytes)
    /// Bytes 8…  : arguments  (size − 8 bytes)
    /// ```
    ///
    /// # Current (stub) behaviour
    ///
    /// Parses wire headers from `wire_bytes`, updates the in-process `SIGNALS`
    /// coverage map, and returns `FuzzOutcome::Ok` without opening a compositor
    /// connection.
    ///
    /// # Intended behaviour
    ///
    /// See the `WlRepeaterFuzzer` struct-level documentation for the full
    /// transition plan and the ready-to-uncomment `Repeater::run` block.
    pub fn fuzz_session(&self, wire_bytes: &[u8]) -> FuzzOutcome {
        // ── Stub: update coverage map from parsed wire message headers ────────
        //
        // Walk every complete 8-byte header in `wire_bytes` and increment the
        // bucket that corresponds to (object_id, opcode).  This gives LibAFL a
        // meaningful novelty signal even without a live compositor: inputs that
        // exercise new object-id × opcode combinations are preserved in the
        // corpus and serve as seeds for the real fuzzing phase.

        let messages = parse_wl_wire_messages(wire_bytes);

        for (object_id, opcode) in &messages {
            let bucket = coverage_bucket(*object_id, *opcode);
            // SAFETY: LibAFL in-process executor is single-threaded; no
            // concurrent mutations of SIGNALS occur.
            unsafe {
                SIGNALS[bucket] = SIGNALS[bucket].saturating_add(1);
            }
        }

        // TODO(M3): replace stub above with Repeater::run (see struct-level
        //           doc for the ready-to-uncomment block).

        // TODO(M3): external compositor health check:
        //
        //     if !compositor_is_alive() {
        //         return FuzzOutcome::Crash {
        //             reason: "compositor exited unexpectedly".to_owned(),
        //         };
        //     }

        FuzzOutcome::Ok
    }
}

// ── Wayland wire-parsing helpers ──────────────────────────────────────────────

/// Parse `bytes` as a flat Wayland wire stream.
///
/// Returns one `(object_id, opcode)` pair for each complete message header
/// encountered.  Incomplete trailing bytes (fewer than 8 bytes remaining, or a
/// declared `size` that overruns the buffer) are silently skipped — fuzzed
/// inputs are expected to be malformed and the parser must not panic.
///
/// This helper is used by the stub `WlRepeaterFuzzer::fuzz_session` to produce
/// a coverage signal without opening a compositor socket.  Once the real
/// `Repeater::run` path is in place this helper can be removed or kept as a
/// lightweight pre-flight check.
fn parse_wl_wire_messages(bytes: &[u8]) -> Vec<(u32, u16)> {
    let mut out = Vec::new();
    let mut off = 0usize;

    while off + 8 <= bytes.len() {
        // Header word 1: object_id
        let object_id = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());

        // Header word 2: opcode (low 16 bits) | size (high 16 bits)
        let word2 = u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap());
        let opcode = (word2 & 0x0000_FFFF) as u16;

        // `size` is the total message length including the 8-byte header.
        // The Wayland wire protocol guarantees size ≥ 8; clamp defensively so
        // a zero-size field in fuzz input does not produce an infinite loop.
        let size = ((word2 >> 16) as usize).max(8);

        out.push((object_id, opcode));

        // Advance past this message; if `size` overruns the buffer we will
        // exit the loop on the next iteration guard.
        off = off.saturating_add(size);
    }

    out
}

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

// ── LibAFL in-process harness ─────────────────────────────────────────────────

/// LibAFL in-process harness function.
///
/// One call to `harness` constitutes one complete fuzzing iteration:
///
/// 1. Interprets `input` as a stream of (potentially malformed) Wayland wire
///    bytes.
/// 2. Forwards them to `WlRepeaterFuzzer::fuzz_session`, which currently only
///    updates the `SIGNALS` coverage map (placeholder behaviour).
/// 3. Maps `FuzzOutcome` to a `ExitKind` for LibAFL:
///    - `Ok`          → `ExitKind::Ok`
///    - `Crash`       → `ExitKind::Crash`   (input saved to crash corpus)
///    - `SetupFailed` → `ExitKind::Ok`      (discard; fix the harness first)
///
/// # Note on per-call allocation
///
/// `WlRepeaterFuzzer` is constructed fresh on every call because the stub
/// implementation carries no persistent state.  Once real compositor
/// connections are added, refactor to capture the fuzzer inside a closure so
/// that the socket connection and protocol data are reused across iterations.
fn harness(input: &BytesInput) -> ExitKind {
    let target = input.target_bytes();
    let data = target.as_slice();

    // TODO(M3): construct WlRepeaterFuzzer once (outside harness) and capture
    // it in a closure passed to InProcessExecutor::new.
    let fuzzer = WlRepeaterFuzzer::new(WlRepeaterConfig::default());

    match fuzzer.fuzz_session(data) {
        FuzzOutcome::Ok => ExitKind::Ok,
        FuzzOutcome::Crash { .. } => ExitKind::Crash,
        FuzzOutcome::SetupFailed { .. } => ExitKind::Ok,
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    // ── Monitor ───────────────────────────────────────────────────────────────
    //
    // Prints fuzzer statistics (executions/s, corpus size, crashes) to stdout.
    let mon = SimpleMonitor::new(|s| println!("{s}"));

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
    // snapshot of it after every harness call.  `MaxMapFeedback` compares the
    // snapshot against a running maximum to decide whether the input is novel.
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
        // TODO(M4): seed from an on-disk corpus of real .wlir recordings.
        InMemoryCorpus::new(),
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
    // `InProcessExecutor` calls `harness` in the same process as the fuzzer.
    // Any panic inside `harness` is caught and mapped to `ExitKind::Crash` by
    // the executor's panic hook (enabled by `panic = "abort"` in profile.dev).
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
    // Seed the corpus with random printable byte arrays as a bootstrapping
    // measure.  LibAFL will mutate and evolve these into structurally diverse
    // Wayland wire streams via `parse_wl_wire_messages`.
    //
    // TODO(M4): replace the random generator below with a corpus loader that
    // reads real `.wlir` trace files from `./corpus/`, converts each recording
    // into its wire-byte representation, and adds it as a `BytesInput` seed.
    // Example sketch:
    //
    //     for entry in fs::read_dir("./corpus")? {
    //         let bytes = fs::read(entry?.path())?;
    //         state.corpus_mut().add(Testcase::new(BytesInput::new(bytes)))?;
    //     }
    let mut generator = RandPrintablesGenerator::new(nonzero!(32));
    state
        .generate_initial_inputs(&mut fuzzer, &mut executor, &mut generator, &mut mgr, 8)
        .expect("failed to generate initial corpus");

    // ── Mutation stage ────────────────────────────────────────────────────────
    //
    // `HavocScheduledMutator` applies a random sequence of byte-level
    // mutations (flips, insertions, deletions, splicing) drawn from the
    // standard `havoc_mutations()` set.  The `StdMutationalStage` wraps it so
    // that the fuzzer applies N mutations per queue entry each round.
    //
    // TODO(M4): add a protocol-aware `WaylandMessageMutator` that respects the
    // Wayland wire header (object_id, opcode, size) so mutations produce valid
    // enough messages to reach deeper compositor logic rather than being
    // rejected at the socket-parsing layer.
    let mutator = HavocScheduledMutator::new(havoc_mutations());
    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    // ── Fuzzing loop ──────────────────────────────────────────────────────────
    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("error in the fuzzing loop");
}
