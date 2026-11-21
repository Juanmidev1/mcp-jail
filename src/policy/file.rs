use std::error::Error;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG_FILE: &str = "mcp-jail.toml";

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyFile {
    pub filesystem: FilesystemSection,
    pub network: NetworkSection,
    pub process: ProcessSection,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FilesystemSection {
    pub ro: Vec<PathBuf>,
    pub rw: Vec<PathBuf>,
    pub allow_env: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_patterns: Option<Vec<String>>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkSection {
    pub deny: bool,
    pub allow_ips: Vec<IpAddr>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessSection {
    pub deny_exec: bool,
}

pub(super) fn load_policy_file(explicit: Option<&Path>) -> Result<PolicyFile, Box<dyn Error>> {
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None if Path::new(DEFAULT_CONFIG_FILE).exists() => PathBuf::from(DEFAULT_CONFIG_FILE),
        None => return Ok(PolicyFile::default()),
    };
    let text = fs::read_to_string(&path)
        .map_err(|e| format!("cannot read policy file {}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("invalid policy file {}: {e}", path.display()).into())
}
