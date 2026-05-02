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

    // On Windows, use two path strategies:
    // 1. \\?\UNC\ (extended-length) for cwd and bin_path — avoids the 260-char
    //    path limit for direct file access.
    // 2. Drive letter via subst for env vars — the Windows WebDAV client
    //    (WebClient service) requires a warm-up read to establish the
    //    connection for each UNC path. Child processes spawned inside
    //    ConPTY sessions don't inherit this connection state, causing
    //    intermittent "path not found" errors on first access. Subst
    //    drive letters avoid this by going through the local filesystem
    //    namespace.
    #[cfg(windows)]
    let _mount = {
        // Map a drive letter for env var paths.
        let mount = WebDavMount::mount(&ctx.webdav_path).unwrap();
        ctx.envs = ctx.envs
            .into_iter()
            .map(|(k, v)| (k, mount.transform_path(&v)))
            .collect();

        // Use \\?\UNC\ for cwd and bin_path (260-char limit avoidance).
        let unc_prefix = format!("\\\\?\\UNC\\{}", ctx.webdav_path.trim_start_matches("\\\\"));
        let webdav_prefix_with_slash = format!("{}\\", ctx.webdav_path);
        let unc_prefix_with_slash = format!("{}\\", unc_prefix);
        let to_unc = |path: &str| -> String {
            path.replace(&webdav_prefix_with_slash, &unc_prefix_with_slash)
        };
        ctx.cwd = to_unc(&ctx.cwd);
        ctx.bin_path = to_unc(&ctx.bin_path);

        mount // keep alive until process exits
    };

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

        // Windows OpenSSH server creates the session process with
        // CREATE_NEW_PROCESS_GROUP, which implicitly sets the per-process
        // CONSOLE_IGNORE_CTRL_C flag (PEB ConsoleFlags). This flag is
        // inherited by all descendants and silently drops CTRL_C_EVENT
        // before it reaches registered handlers. Clear it so that child
        // processes (e.g. ConPTY-based tests) can receive Ctrl+C normally.
        // SAFETY: Clearing the inherited CTRL_C ignore flag with valid Win32 API args.
        unsafe {
            unsafe extern "system" {
                fn SetConsoleCtrlHandler(
                    handler: Option<unsafe extern "system" fn(u32) -> i32>,
                    add: i32,
                ) -> i32;
            }
            SetConsoleCtrlHandler(None, 0); // 0 = FALSE = clear ignore flag
        }

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
