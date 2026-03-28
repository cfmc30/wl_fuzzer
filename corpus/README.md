# Seed Corpus

Put real `.wlir` recordings in this directory. Each file must be a complete
recording that `wl_repeater::ir::IrReader::from_bytes` can parse from start to
finish.

Good seeds come from `wl_tracer` runs or from existing captured recordings.
The goal is to replay realistic protocol traffic, not random byte strings.
The fuzzer does not bootstrap from printable-random bytes anymore.

Startup requires at least one real `.wlir` file in this directory and exits
before entering the fuzz loop if the directory has no usable seeds. Do not
handcraft fake `.wlir` files when a real recording is available.

Current boundary: these seeds are replayed by an in-process harness, so replay
failures are still only a rough proxy for compositor crashes, and coverage
still comes from the local `SIGNALS` heuristic in `wl_fuzzer/src/main.rs`.

Next milestone: add compositor supervision and crash classification so replay
results can distinguish malformed inputs from real compositor exits or hangs.

Milestone after that: replace the local heuristic with shared-memory coverage
exported by an instrumented compositor binary.
