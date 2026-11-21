use std::error::Error;
use std::path::Path;

use ::landlock::{
    ABI, Access, AccessFs, BitFlags, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetStatus,
};

use crate::policy::Policy;

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;

// Highest ABI requested; the crate's best-effort mode drops rights older kernels lack
const TARGET_ABI: ABI = ABI::V5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockStatus {
    Enforced,
    UnsupportedKernel,
}

/// Opens every rule path in the parent so `enforce` can run after fork without allocating
pub fn prepare_ruleset(policy: &Policy) -> Result<RulesetCreated, Box<dyn Error>> {
    let read_access = AccessFs::from_read(TARGET_ABI);
    let full_access = AccessFs::from_all(TARGET_ABI);
    let mut ruleset = Ruleset::default().handle_access(full_access)?.create()?;
    for path in &policy.ro {
        ruleset = add_path_rule(ruleset, path, read_access)?;
    }
    for path in &policy.rw {
        ruleset = add_path_rule(ruleset, path, full_access)?;
    }
    Ok(ruleset)
}

/// Must be async-signal-safe: it is called from `pre_exec` in the forked child
pub fn enforce(ruleset: RulesetCreated) -> Result<LandlockStatus, Box<dyn Error>> {
    let status = ruleset.restrict_self()?;
    Ok(match status.ruleset {
        RulesetStatus::NotEnforced => LandlockStatus::UnsupportedKernel,
        RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced => LandlockStatus::Enforced,
    })
}

pub fn is_supported() -> bool {
    let abi_version = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    abi_version >= 1
}

fn add_path_rule(
    ruleset: RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
) -> Result<RulesetCreated, Box<dyn Error>> {
    if !path.exists() {
        return Ok(ruleset);
    }
    let path_fd = PathFd::new(path)
        .map_err(|e| format!("cannot open Landlock rule path {}: {e}", path.display()))?;
    Ok(ruleset.add_rule(PathBeneath::new(path_fd, access))?)
}

#[cfg(test)]
mod tests;
