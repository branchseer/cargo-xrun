mod config;

use std::ffi::OsStr;

pub fn runner(target: &str, exe: &OsStr) -> anyhow::Result<()> {
    for (name, value) in std::env::vars_os() {
        dbg!((name, value));
    }
    println!("Running {:?} for target {}", exe, target);
    Ok(())
}
