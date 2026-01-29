#[cfg(feature = "decode")]
use wincode::SchemaRead;
#[cfg(feature = "encode")]
use wincode::SchemaWrite;

/// Execution context passed from host to remote binary.
#[cfg_attr(feature = "encode", derive(SchemaWrite))]
#[cfg_attr(feature = "decode", derive(SchemaRead))]
#[derive(Debug, Clone)]
pub struct ExecContext {
    pub cwd: String,
    pub envs: Vec<(String, String)>,
    pub bin_path: String,
    pub args: Vec<String>,
    pub webdav_path: String,
}

#[cfg(feature = "encode")]
pub mod encode {
    use super::ExecContext;
    use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};

    pub fn encode_context(ctx: &ExecContext) -> String {
        let bytes = wincode::serialize(ctx).unwrap();
        URL_SAFE_NO_PAD.encode(&bytes)
    }
}

#[cfg(feature = "decode")]
pub mod decode {
    use super::ExecContext;
    use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};

    pub fn decode_context(encoded: &str) -> Result<ExecContext, Box<dyn std::error::Error>> {
        let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
        let ctx = wincode::deserialize(&bytes)?;
        Ok(ctx)
    }
}

#[cfg(all(feature = "decode", windows))]
struct WebDavMount {
    drive_letter: String,
    webdav_prefix: String,
}

#[cfg(all(feature = "decode", windows))]
impl WebDavMount {
    fn mount(webdav_path: &str) -> Result<Self, std::io::Error> {
        use std::process::Command;

        // Try drive letters from Z: down to A:
        let mut last_error = None;
        for letter in (b'A'..=b'Z').rev() {
            let drive_letter = format!("{}:", letter as char);

            // Try to create drive mapping with subst
            let output = Command::new("subst")
                .args(&[&drive_letter, webdav_path])
                .output()?;

            if output.status.success() {
                return Ok(WebDavMount {
                    drive_letter,
                    webdav_prefix: webdav_path.to_string(),
                });
            }

            // Subst failed - check if it's a drive-in-use error or something else
            let check_output = Command::new("subst").output()?;
            if check_output.status.success() {
                let stdout = String::from_utf8_lossy(&check_output.stdout);
                // If this drive letter appears in "subst" output, it's already mapped
                if stdout.contains(&drive_letter) {
                    // Drive letter in use, try next one
                    continue;
                }
            }

            // Drive isn't in subst list, so the error is something else (e.g., path not found)
            // Save this error and try next letter, but if all fail, return this error
            if last_error.is_none() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let stdout = String::from_utf8_lossy(&output.stdout);
                last_error = Some(format!("{}{}", stderr, stdout).trim().to_string());
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            last_error.unwrap_or_else(|| "No available drive letters".to_string())
        ))
    }

    fn transform_path(&self, path: &str) -> String {
        // Replace ALL occurrences of the webdav_prefix with drive letter
        // e.g., "\\localhost@port\DavWWWRoot\" -> "Z:\"
        // So "\\localhost@port\DavWWWRoot\fs\C:\path" becomes "Z:\fs\C:\path"
        let prefix_with_slash = format!("{}\\", self.webdav_prefix);
        path.replace(&prefix_with_slash, &format!("{}\\", self.drive_letter))
    }
}

#[cfg(all(feature = "decode", windows))]
impl Drop for WebDavMount {
    fn drop(&mut self) {
        use std::process::Command;

        // Best effort unmount using subst /d - ignore errors
        let _ = Command::new("subst")
            .args(&[&self.drive_letter, "/d"])
            .output();
    }
}

#[cfg(feature = "decode")]
pub fn main() -> std::process::ExitCode {
    use std::{env, process::Command};

    let args: Vec<String> = env::args().collect();
    #[cfg(windows)]
    let mut ctx = decode::decode_context(&args[1]).unwrap();
    #[cfg(not(windows))]
    let ctx = decode::decode_context(&args[1]).unwrap();

    // On Windows, mount WebDAV path to drive letter
    #[cfg(windows)]
    let _mount = {
        // Mount the WebDAV root directly - no delay needed since UNC paths work immediately
        match WebDavMount::mount(&ctx.webdav_path) {
            Ok(mount) => {
                // Transform all paths by replacing ALL occurrences of WebDAV prefix
                ctx.cwd = mount.transform_path(&ctx.cwd);
                ctx.bin_path = mount.transform_path(&ctx.bin_path);
                ctx.envs = ctx.envs
                    .into_iter()
                    .map(|(k, v)| (k, mount.transform_path(&v)))
                    .collect();

                // Change to the transformed path (now using drive letter)
                env::set_current_dir(&ctx.cwd).unwrap();

                mount
            }
            Err(e) => {
                use std::process::ExitCode;
                eprintln!("cargo-xrun-remote: Failed to mount WebDAV drive: {}", e);
                return ExitCode::from(1);
            }
        }
    };

    #[cfg(not(windows))]
    env::set_current_dir(&ctx.cwd).unwrap();

    let mut cmd = Command::new(&ctx.bin_path);
    for (name, value) in &ctx.envs {
        cmd.env(name, value);
    }
    cmd.args(&ctx.args);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        panic!("cargo-xrun-remote: {}", err);
    }

    #[cfg(windows)]
    {
        use std::process::ExitCode;
        let status = match cmd.status() {
            Ok(s) => s,
            Err(err) if err.kind() == std::io::ErrorKind::FileTooLarge => {
                eprintln!(
                    r#"cargo-xrun-remote: The executable size exceeds the limit allowed by Windows WebDav Client.
To raise the limit, update FileSizeLimitInBytes in HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient\Parameters,
and then restart the WebClient service."#
                );
                return ExitCode::from(1);
            }
            Err(err) => {
                eprintln!(
                    "cargo-xrun-remote: Failed to execute remote binary: {}",
                    err
                );
                return ExitCode::from(1);
            }
        };
        ExitCode::from(status.code().unwrap_or(1) as u8)
    }
}
