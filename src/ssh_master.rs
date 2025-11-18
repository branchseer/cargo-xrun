use std::{
    any,
    mem::ManuallyDrop,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
};

use anyhow::Context as _;
use send_ctrlc::{Interruptible, InterruptibleCommand, tokio::InterruptibleChild};
use tempfile::NamedTempFile;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    process::Command,
};

pub struct SshMaster {
    control_path: NamedTempFile<PathBuf>,
    master_daemon: InterruptibleChild,
    remote_port: u16,
}

impl SshMaster {
    pub fn control_path(&self) -> &Path {
        self.control_path.as_file().as_path()
    }
    pub fn remote_port(&self) -> u16 {
        self.remote_port
    }
    pub async fn start(ssh_destination: &str, forward_port: u16) -> anyhow::Result<Self> {
        let control_path = tempfile::Builder::new().make(|path: &Path| Ok(path.to_path_buf()))?;

        let mut master_daemon = Command::new("ssh")
            .args([
                "-R",
                &format!("0:localhost:{}", forward_port), // remote port forwarding
                "-o",
                "ExitOnForwardFailure=yes",
                "-M", // master mode
                "-S", // socket path
            ])
            .arg(control_path.as_file().as_os_str())
            .arg(ssh_destination)
            .arg("sc start WebClient >nul 2>nul & pause >nul 2>nul")
            .stderr(Stdio::piped())
            .spawn_interruptible()
            .context("Failed to spawn ssh master daemon")?;

        let remote_port: Option<u16> = {
            let mut master_daemon_stderr = BufReader::new(master_daemon.stderr.take().unwrap());
            let mut line_buf = String::new();
            let mut stderr = tokio::io::stderr();
            const ALLOCATED_PORT_PREFIX: &str = "Allocated port ";
            loop {
                let n = master_daemon_stderr.read_line(&mut line_buf).await?;
                if n == 0 {
                    break None;
                }
                let line = &line_buf[..n];
                if line.starts_with(ALLOCATED_PORT_PREFIX) {
                    let port_str = line[ALLOCATED_PORT_PREFIX.len()..]
                        .split_whitespace()
                        .next()
                        .context("Failed to parse allocated port from ssh output")?;
                    let port: u16 = port_str.parse().context("Failed to parse allocated port")?;
                    break Some(port);
                }
                stderr.write_all(line.as_bytes()).await?;
                line_buf.clear();
            }
        };

        let Some(remote_port) = remote_port else {
            let status = master_daemon.wait().await?;
            anyhow::bail!(
                "ssh exited without allocating a remote port (status {:?})",
                status
            );
        };

        Ok(Self {
            control_path,
            master_daemon,
            remote_port,
        })
    }

    pub async fn stop(mut self) -> anyhow::Result<ExitStatus> {
        self.master_daemon.interrupt()?;
        let mut me = ManuallyDrop::new(self);
        Ok(me.master_daemon.wait().await?)
    }
}

impl Drop for SshMaster {
    fn drop(&mut self) {
        if let Err(err) = self.master_daemon.interrupt() {
            tracing::warn!("Failed to interrupt ssh master daemon: {:?}", err);
        }
    }
}
