use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

pub type ConfigResult<T> = Result<T, String>;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub corpus_dir: PathBuf,
    pub crashes_dir: PathBuf,
    pub protocol_dirs: Vec<PathBuf>,
    #[serde(default)]
    pub verbose: bool,
    #[serde(default = "default_server_wait_timeout_ms")]
    pub server_wait_timeout_ms: u64,
    pub targets: Vec<TargetConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    pub name: String,
    pub xdg_runtime_dir: PathBuf,
    pub display: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedReplayConfig {
    pub protocol_dirs: Vec<PathBuf>,
    pub verbose: bool,
    pub server_wait_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRuntimeConfig {
    pub corpus_dir: PathBuf,
    pub crashes_dir: PathBuf,
    pub replay: SharedReplayConfig,
    pub targets: [TargetConfig; 2],
}

fn default_server_wait_timeout_ms() -> u64 {
    100
}

pub fn parse_config_path(args: &[String]) -> ConfigResult<PathBuf> {
    match args {
        [_, flag, path] if flag == "--config" => Ok(PathBuf::from(path)),
        _ => Err("usage: wl_fuzzer --config <path>".to_owned()),
    }
}

pub fn load_runtime_config(path: &Path) -> ConfigResult<ValidatedRuntimeConfig> {
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let yaml = fs::read_to_string(path)
        .map_err(|err| format!("failed to read config {}: {err}", path.display()))?;
    let mut config = load_runtime_config_from_str(&yaml)?;
    config.corpus_dir = resolve_config_path(config_dir, config.corpus_dir);
    config.crashes_dir = resolve_config_path(config_dir, config.crashes_dir);
    config.replay.protocol_dirs = config
        .replay
        .protocol_dirs
        .into_iter()
        .map(|path| resolve_config_path(config_dir, path))
        .collect();
    for target in &mut config.targets {
        target.xdg_runtime_dir = resolve_config_path(config_dir, target.xdg_runtime_dir.clone());
    }
    Ok(config)
}

pub fn load_runtime_config_from_str(yaml: &str) -> ConfigResult<ValidatedRuntimeConfig> {
    let raw: RuntimeConfig =
        serde_yaml::from_str(yaml).map_err(|err| format!("failed to parse YAML config: {err}"))?;
    raw.validate()
}

impl RuntimeConfig {
    fn validate(self) -> ConfigResult<ValidatedRuntimeConfig> {
        if self.corpus_dir.as_os_str().is_empty() {
            return Err("corpus_dir must not be empty".to_owned());
        }

        if self.crashes_dir.as_os_str().is_empty() {
            return Err("crashes_dir must not be empty".to_owned());
        }

        if self.protocol_dirs.is_empty() {
            return Err("protocol_dirs must not be empty".to_owned());
        }

        for (index, protocol_dir) in self.protocol_dirs.iter().enumerate() {
            if protocol_dir.as_os_str().is_empty() {
                return Err(format!("protocol_dirs[{index}] must not be empty"));
            }
        }

        if self.targets.len() != 2 {
            return Err("runtime config must contain exactly two targets".to_owned());
        }

        let mut validated_targets = Vec::with_capacity(2);
        for (index, target) in self.targets.into_iter().enumerate() {
            if target.name.trim().is_empty() {
                return Err(format!("targets[{index}].name must not be empty"));
            }
            if target.display.trim().is_empty() {
                return Err(format!("targets[{index}].display must not be empty"));
            }
            if target.xdg_runtime_dir.as_os_str().is_empty() {
                return Err(format!(
                    "targets[{index}].xdg_runtime_dir must not be empty"
                ));
            }
            validated_targets.push(target);
        }

        let [left, right]: [TargetConfig; 2] = validated_targets
            .try_into()
            .map_err(|_| "runtime config must contain exactly two targets".to_owned())?;

        Ok(ValidatedRuntimeConfig {
            corpus_dir: self.corpus_dir,
            crashes_dir: self.crashes_dir,
            replay: SharedReplayConfig {
                protocol_dirs: self.protocol_dirs,
                verbose: self.verbose,
                server_wait_timeout_ms: self.server_wait_timeout_ms,
            },
            targets: [left, right],
        })
    }
}

fn resolve_config_path(base_dir: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}
