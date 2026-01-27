mod config_file;

use std::{fmt::Display, fs::File, io::{Read as _, Seek as _, SeekFrom, Write as _}};

use anyhow::Context as _;
use config_file::{upsert_with, Host, UserResponse};
use inquire::{InquireError, Select, Text, error::InquireResult, validator::Validation};

fn prompt_for_host_selection(
    existing_hosts: &[config_file::Host],
    target: &str,
) -> InquireResult<config_file::UserResponse> {
    if existing_hosts.is_empty() {
        // No hosts configured yet
        println!("No remote hosts configured for {} yet.", target);
        let destination = Text::new("Enter SSH destination:")
            .with_placeholder("user@server.com")
            .with_validator(|input: &str| {
                if input.trim().is_empty() {
                    Ok(Validation::Invalid("Destination cannot be empty".into()))
                } else {
                    Ok(Validation::Valid)
                }
            })
            .prompt()?;
        return Ok(UserResponse::AddNewHost { destination });
    }

    // Build options: existing hosts + "Add new host"
    enum SelectOption {
        ExistingHost { host: Host, index: usize },
        AddNewHost,
    }
    impl Display for SelectOption {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                SelectOption::ExistingHost { host, .. } => {
                    write!(
                        f,
                        "{} (targets: {})",
                        host.destination,
                        host.targets.join(", ")
                    )
                }
                SelectOption::AddNewHost => write!(f, "Add a new remote host"),
            }
        }
    }
    let mut options: Vec<SelectOption> = existing_hosts
        .iter()
        .enumerate()
        .map(|(index, host)| SelectOption::ExistingHost {
            host: host.clone(),
            index,
        })
        .collect();
    options.push(SelectOption::AddNewHost);

    let selection = Select::new(&format!("Select host for target '{}':", target), options)
        .without_filtering()
        .prompt()?;

    // Check if user selected "Add new host"
    match selection {
        SelectOption::AddNewHost => {
            let destination = Text::new("Enter SSH destination:")
                .with_placeholder("e.g., user@server.com")
                .with_validator(|input: &str| {
                    if input.trim().is_empty() {
                        Ok(Validation::Invalid("Destination cannot be empty".into()))
                    } else {
                        Ok(Validation::Valid)
                    }
                })
                .prompt()?;
            Ok(UserResponse::AddNewHost { destination })
        }
        SelectOption::ExistingHost { index, .. } => {
            Ok(UserResponse::AddTargetToHost { host_index: index })
        }
    }
}

pub fn get_ssh_destination(target: &str) -> anyhow::Result<String> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?
        .join("cargo-xrun");
    std::fs::create_dir_all(&config_dir)?;

    let config_path = config_dir.join("config.json");

    // Create or open config file
    let mut json_config_file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .open(&config_path)
        .with_context(|| format!("Failed to open or create config file at {:?}", &config_path))?;

    let mut json_config_str = String::new();
    json_config_file
        .read_to_string(&mut json_config_str)
        .context(format!("Failed to read config file at {:?}", &config_path))?;

    let host = upsert_with(&mut json_config_str, target, |existing_hosts| {
        match prompt_for_host_selection(existing_hosts, target) {
            Ok(user_response) => Ok(user_response),
            Err(InquireError::OperationCanceled | InquireError::OperationInterrupted) => {
                std::process::exit(0)
            }
            Err(err) => Err(anyhow::Error::from(err).context("Failed during prompt")),
        }
    })?;

    json_config_file.set_len(0)?;
    json_config_file.seek(SeekFrom::Start(0))?;
    json_config_file.write_all(json_config_str.as_bytes())?;

    Ok(host.destination)
}
