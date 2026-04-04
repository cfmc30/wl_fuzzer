use std::{
    error::Error,
    fs, io,
    path::{Path, PathBuf},
};

use wl_repeater::{protocol::Protocol, repeater::Repeater, ReplaySummary};

use crate::{
    config::{SharedReplayConfig, TargetConfig},
    wlir_input::WlirInput,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayOutcome {
    Ok,
    DisconnectedOrCrashed { reason: String },
    SetupFailed { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DifferentialOutcome {
    EquivalentOk,
    EquivalentFailure,
    DivergentFailure { left: String, right: String },
    SetupNoise,
}

#[derive(Debug, Clone)]
pub struct ReplayExecutor {
    shared: SharedReplayConfig,
    target: TargetConfig,
}

#[derive(Debug, Clone)]
pub struct DifferentialExecutor {
    left: ReplayExecutor,
    right: ReplayExecutor,
}

pub fn compare_replay_outcomes(left: &ReplayOutcome, right: &ReplayOutcome) -> DifferentialOutcome {
    match (left, right) {
        (ReplayOutcome::SetupFailed { .. }, _) | (_, ReplayOutcome::SetupFailed { .. }) => {
            DifferentialOutcome::SetupNoise
        }
        (ReplayOutcome::Ok, ReplayOutcome::Ok) => DifferentialOutcome::EquivalentOk,
        (
            ReplayOutcome::DisconnectedOrCrashed { .. },
            ReplayOutcome::DisconnectedOrCrashed { .. },
        ) => DifferentialOutcome::EquivalentFailure,
        _ => DifferentialOutcome::DivergentFailure {
            left: describe_outcome(left),
            right: describe_outcome(right),
        },
    }
}

impl ReplayExecutor {
    pub fn new(shared: SharedReplayConfig, target: TargetConfig) -> Self {
        Self { shared, target }
    }

    pub fn run(&self, input: &WlirInput) -> ReplayOutcome {
        let mut repeater =
            match build_repeater(&self.shared, &self.target, input.header.start_time_us) {
                Ok(repeater) => repeater,
                Err(err) => {
                    return ReplayOutcome::SetupFailed {
                        reason: format!(
                            "{}: failed to build wl_repeater session: {err}",
                            self.target.name
                        ),
                    };
                }
            };

        classify_replay_result(
            &self.target.name,
            repeater.run_from_messages(input.messages.clone()),
        )
    }
}

pub(crate) fn resolve_target_display_path(target: &TargetConfig) -> PathBuf {
    let display = Path::new(&target.display);
    if display.is_absolute() {
        display.to_path_buf()
    } else {
        target.xdg_runtime_dir.join(display)
    }
}

fn target_display_arg(target: &TargetConfig) -> String {
    resolve_target_display_path(target).display().to_string()
}

impl DifferentialExecutor {
    pub fn new(shared: SharedReplayConfig, targets: [TargetConfig; 2]) -> Self {
        let [left, right] = targets;
        Self {
            left: ReplayExecutor::new(shared.clone(), left),
            right: ReplayExecutor::new(shared, right),
        }
    }

    pub fn run(&self, input: &WlirInput) -> DifferentialOutcome {
        let left = self.left.run(input);
        let right = self.right.run(input);
        compare_replay_outcomes(&left, &right)
    }
}

pub(crate) fn build_repeater(
    shared: &SharedReplayConfig,
    target: &TargetConfig,
    start_time_us: u64,
) -> io::Result<Repeater> {
    let protocol = load_protocols(&shared.protocol_dirs)
        .map_err(|err| io::Error::other(format!("failed to load protocols: {err}")))?;
    let display = target_display_arg(target);

    Repeater::new(
        &display,
        shared.verbose,
        false,
        false,
        shared.server_wait_timeout_ms,
        start_time_us,
        protocol,
    )
}

pub fn classify_replay_result(
    target_name: &str,
    result: io::Result<ReplaySummary>,
) -> ReplayOutcome {
    match result {
        Ok(_) => ReplayOutcome::Ok,
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
            ) =>
        {
            ReplayOutcome::SetupFailed {
                reason: format!("{target_name}: replay rejected malformed .wlir input: {err}"),
            }
        }
        Err(err) => ReplayOutcome::DisconnectedOrCrashed {
            reason: format!("{target_name}: replay failed: {err}"),
        },
    }
}

pub fn load_protocols(paths: &[PathBuf]) -> Result<Protocol, Box<dyn Error>> {
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

fn describe_outcome(outcome: &ReplayOutcome) -> String {
    match outcome {
        ReplayOutcome::Ok => "ok".to_owned(),
        ReplayOutcome::DisconnectedOrCrashed { reason } | ReplayOutcome::SetupFailed { reason } => {
            reason.clone()
        }
    }
}
