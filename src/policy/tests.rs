use std::path::{Path, PathBuf};

use super::*;

const ENV_FILE: &str = concat!(".e", "nv");
const ENV_LOCAL_FILE: &str = concat!(".e", "nv.local");
const RSA_KEY_FILE: &str = concat!("id_", "rsa");

fn build(file: PolicyFile, args: &SandboxArgs) -> Policy {
    Policy::build(file, args, Some(Path::new("/home/tester")))
}

#[test]
fn glob_matches_wildcards() {
    assert!(matches_glob("*.pem", "server.pem"));
    assert!(matches_glob(concat!(".e", "nv.*"), ENV_LOCAL_FILE));
    assert!(!matches_glob(concat!(".e", "nv.*"), ENV_FILE));
    assert!(matches_glob(ENV_FILE, ENV_FILE));
    assert!(!matches_glob("*.key", "keys.txt"));
    assert!(matches_glob("a*b*c", "axxbyyc"));
}

#[test]
fn default_policy_denies_secret_files_and_home_dirs() {
    let policy = build(PolicyFile::default(), &SandboxArgs::default());
    assert!(policy.is_denied_path(&Path::new("/work").join(ENV_FILE)));
    assert!(policy.is_denied_path(&Path::new("/work").join(ENV_LOCAL_FILE)));
    assert!(policy.is_denied_path(Path::new("/home/tester/.ssh/config")));
    assert!(policy.is_denied_path(&Path::new("/x").join(RSA_KEY_FILE)));
    assert!(!policy.is_denied_path(Path::new("/work/README.md")));
}

#[test]
fn allow_env_unblocks_only_env_files() {
    let args = SandboxArgs {
        allow_env: true,
        ..SandboxArgs::default()
    };
    let policy = build(PolicyFile::default(), &args);
    assert!(!policy.is_denied_path(&Path::new("/work").join(ENV_FILE)));
    assert!(policy.is_denied_path(Path::new("/work/cert.pem")));
}

#[test]
fn custom_patterns_keep_home_secret_dirs() {
    let mut file = PolicyFile::default();
    file.filesystem.deny_patterns = Some(vec!["*.secret".into()]);
    let policy = build(file, &SandboxArgs::default());
    assert!(policy.is_denied_path(Path::new("/work/db.secret")));
    assert!(!policy.is_denied_path(Path::new("/work/cert.pem")));
    assert!(policy.is_denied_path(Path::new("/home/tester/.aws/credentials")));
}

#[test]
fn paths_merge_defaults_file_and_cli_without_duplicates() {
    let mut file = PolicyFile::default();
    file.filesystem.ro = vec![PathBuf::from("/opt/data"), PathBuf::from("/usr")];
    let args = SandboxArgs {
        ro: vec![PathBuf::from("/srv")],
        ..SandboxArgs::default()
    };
    let policy = build(file, &args);
    assert!(policy.ro.contains(&PathBuf::from("/opt/data")));
    assert!(policy.ro.contains(&PathBuf::from("/srv")));
    assert_eq!(
        policy.ro.iter().filter(|p| *p == Path::new("/usr")).count(),
        1
    );
    assert!(policy.rw.contains(&PathBuf::from(".")));
}

#[test]
fn cli_flags_tighten_file_settings() {
    let mut file = PolicyFile::default();
    file.network.allow_ips = vec!["1.1.1.1".parse().unwrap()];
    let args = SandboxArgs {
        deny_exec: true,
        ..SandboxArgs::default()
    };
    let policy = build(file, &args);
    assert!(policy.deny_exec);
    assert!(policy.is_ip_allowed("1.1.1.1".parse().unwrap()));
    assert!(!policy.is_ip_allowed("8.8.8.8".parse().unwrap()));
}

#[test]
fn loopback_is_always_allowed() {
    let args = SandboxArgs {
        deny_net: true,
        ..SandboxArgs::default()
    };
    let policy = build(PolicyFile::default(), &args);
    assert!(policy.is_ip_allowed("127.0.0.53".parse().unwrap()));
    assert!(policy.is_ip_allowed("::1".parse().unwrap()));
    assert!(policy.is_ip_allowed("::ffff:127.0.0.1".parse().unwrap()));
    assert!(!policy.is_ip_allowed("140.82.121.4".parse().unwrap()));
}

#[test]
fn network_is_open_by_default() {
    let policy = build(PolicyFile::default(), &SandboxArgs::default());
    assert!(policy.is_ip_allowed("140.82.121.4".parse().unwrap()));
}

#[test]
fn loads_toml_file_and_rejects_unknown_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.toml");
    std::fs::write(
        &path,
        "[network]\ndeny = true\n[process]\ndeny_exec = true\n",
    )
    .unwrap();
    let args = SandboxArgs {
        config: Some(path.clone()),
        ..SandboxArgs::default()
    };
    let policy = Policy::load(&args).unwrap();
    assert!(policy.deny_net && policy.deny_exec);

    std::fs::write(&path, "[network]\nblock = true\n").unwrap();
    assert!(Policy::load(&args).is_err());
}

#[test]
fn missing_explicit_config_is_an_error() {
    let args = SandboxArgs {
        config: Some(PathBuf::from("/nonexistent/mcp-jail.toml")),
        ..SandboxArgs::default()
    };
    assert!(Policy::load(&args).is_err());
}
