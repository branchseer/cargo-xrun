use std::{
    collections::HashMap,
    env,
    ffi::{OsStr, OsString},
    process::ExitCode,
};

use anyhow::Context as _;
use tokio::process::Command;

pub async fn runner(
    target: &str,
    mut args: impl Iterator<Item = impl AsRef<OsStr>>,
    ssh_ctrl_path: &OsStr,
    ssh_remote_fs_server_port: u16,
    ssh_destination: &str,
) -> anyhow::Result<ExitCode> {
    let remote_path_root = format!("\\\\localhost@{}\\DavWWWRoot", ssh_remote_fs_server_port);

    let to_remote_path = |path: &OsStr| -> anyhow::Result<String> {
        let path = std::path::absolute(path)?
            .into_os_string()
            .into_string()
            .ok()
            .context("Invalid path")?;
        if path.contains(char::is_whitespace) {
            anyhow::bail!(
                "Path contains whitespace, which is not supported for remote execution: {}",
                path
            );
        }
        let path = path.replace("/", "\\");
        Ok(format!(
            "{}\\{}",
            remote_path_root,
            path.trim_start_matches('\\')
        ))
    };

    let mut envs = HashMap::<String, String>::new();
    for (env_name, env_value) in std::env::vars_os() {
        let Ok(env_name) = env_name.into_string() else {
            continue;
        };
        if env_name == "CARGO"
            || env_name == "CARGO_MANIFEST_DIR"
            || env_name == "CARGO_MANIFEST_PATH"
            || env_name.starts_with("CARGO_BIN_EXE_")
        {
            let env_value = to_remote_path(&env_value)?;
            envs.insert(env_name, env_value.into());
        } else if env_name.starts_with("CARGO_") {
            let env_value = env_value.into_string().ok().context("Invalid env value")?;
            envs.insert(env_name, env_value);
        }
    }

    let mut command = Command::new("ssh");
    command
        .arg("-S")
        .arg(ssh_ctrl_path)
        .args(["-o", "PreferredAuthentications=none"]) // force to use control path
        .arg(ssh_destination)
        .arg("powershell.exe")
        .arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-Command");

    // Set remote working directory
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let remote_cwd = to_remote_path(cwd.as_os_str())?;
    // command.arg("cd");
    // command.arg(&remote_cwd);
    // command.arg("&&");

    for (env_name, env_value) in envs {
        command.arg(format!("$env:{}='{}'", env_name, env_value));
        command.arg("&&");
    }

    let exe = args.next().context("executable argument missing")?;
    command.arg(to_remote_path(exe.as_ref())?);
    command.args(args);

    let status = command.status().await?;
    Ok((status.code().unwrap_or(1) as u8).into())
}
