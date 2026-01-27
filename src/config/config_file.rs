use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Host {
    pub destination: String,
    pub targets: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ConfigFile {
    host: Vec<Host>,
}

pub enum UserResponse {
    AddTargetToHost { host_index: usize },
    AddNewHost { destination: String },
}

/// Upsert a host configuration for the given target.
///
/// If a host already exists for the target, return it.
///
/// Otherwise,
/// 1. invoke the provided closure to get user input on whether to add the target to an existing host or create a new host,
/// 2. perform the edit on `json_config_str`.
/// 3. return the newly created or updated host.
///
/// Returns an error if the JSON is malformed or has invalid schema.
pub fn upsert_with(
    json_config_str: &mut String,
    target: &str,
    f: impl FnOnce(&[Host]) -> anyhow::Result<UserResponse>,
) -> anyhow::Result<Host> {
    // Parse JSON config, treating empty string as empty host list
    let mut config: ConfigFile = if json_config_str.trim().is_empty() {
        ConfigFile::default()
    } else {
        serde_json::from_str(json_config_str).context("Failed to parse JSON configuration")?
    };

    // Check if target already exists in any host
    for host in &config.host {
        if host.targets.contains(&target.to_string()) {
            return Ok(host.clone());
        }
    }

    // Target doesn't exist, get user's choice
    let user_response = f(&config.host)?;

    match user_response {
        UserResponse::AddTargetToHost { host_index } => {
            // Add target to existing host's targets array
            let host = config
                .host
                .get_mut(host_index)
                .ok_or_else(|| anyhow!("Invalid host_index: {}", host_index))?;
            host.targets.push(target.to_string());

            // Update the string with pretty formatting
            *json_config_str =
                serde_json::to_string_pretty(&config).context("Failed to serialize config to JSON")?;

            Ok(config.host[host_index].clone())
        }
        UserResponse::AddNewHost { destination } => {
            // Check if a host with this destination already exists
            let existing_index = config.host.iter().position(|h| h.destination == destination);

            if let Some(index) = existing_index {
                config.host[index].targets.push(target.to_string());

                *json_config_str =
                    serde_json::to_string_pretty(&config).context("Failed to serialize config to JSON")?;

                Ok(config.host[index].clone())
            } else {
                // Create a new host entry
                let new_host = Host {
                    destination,
                    targets: vec![target.to_string()],
                };
                config.host.push(new_host.clone());

                // Update the string with pretty formatting
                *json_config_str =
                    serde_json::to_string_pretty(&config).context("Failed to serialize config to JSON")?;

                Ok(new_host)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_upsert_with_existing_target() {
        let mut config_str = String::from(
            r#"{
  "host": [
    {
      "destination": "user@server1.com",
      "targets": ["aarch64-apple-darwin", "x86_64-apple-darwin"]
    },
    {
      "destination": "user@server2.com",
      "targets": ["x86_64-unknown-linux-gnu"]
    }
  ]
}"#,
        );

        // Target already exists, should return existing host without calling closure
        let result = upsert_with(&mut config_str, "x86_64-apple-darwin", |_hosts| {
            panic!("Closure should not be called when target already exists");
        })
        .expect("test should succeed");

        assert_eq!(result.destination, "user@server1.com");
        assert_eq!(result.targets.len(), 2);
        assert!(result.targets.contains(&"x86_64-apple-darwin".to_string()));

        // Config string should contain both hosts
        assert!(config_str.contains("user@server1.com"));
        assert!(config_str.contains("user@server2.com"));
    }

    #[test]
    fn test_upsert_with_add_target_to_existing_host() {
        let mut config_str = String::from(
            r#"{
  "host": [
    {
      "destination": "user@server1.com",
      "targets": ["aarch64-apple-darwin"]
    },
    {
      "destination": "user@server2.com",
      "targets": ["x86_64-unknown-linux-gnu"]
    }
  ]
}"#,
        );

        let original_config = config_str.clone();

        // Add new target to first host
        let result = upsert_with(&mut config_str, "x86_64-apple-darwin", |hosts| {
            assert_eq!(hosts.len(), 2);
            assert_eq!(hosts[0].destination, "user@server1.com");
            Ok(UserResponse::AddTargetToHost { host_index: 0 })
        })
        .expect("test should succeed");

        assert_eq!(result.destination, "user@server1.com");
        assert_eq!(result.targets.len(), 2);
        assert!(result.targets.contains(&"aarch64-apple-darwin".to_string()));
        assert!(result.targets.contains(&"x86_64-apple-darwin".to_string()));

        // Verify the config string was updated
        assert_ne!(config_str, original_config);
        assert!(config_str.contains("x86_64-apple-darwin"));

        // Verify second host is unchanged
        assert!(config_str.contains("user@server2.com"));
        assert!(config_str.contains("x86_64-unknown-linux-gnu"));
    }

    #[test]
    fn test_upsert_with_add_target_to_second_host() {
        let mut config_str = String::from(
            r#"{
  "host": [
    {
      "destination": "user@server1.com",
      "targets": ["aarch64-apple-darwin"]
    },
    {
      "destination": "user@server2.com",
      "targets": ["x86_64-unknown-linux-gnu"]
    }
  ]
}"#,
        );

        // Add new target to second host
        let result = upsert_with(&mut config_str, "aarch64-unknown-linux-gnu", |hosts| {
            assert_eq!(hosts.len(), 2);
            assert_eq!(hosts[1].destination, "user@server2.com");
            Ok(UserResponse::AddTargetToHost { host_index: 1 })
        })
        .expect("test should succeed");

        assert_eq!(result.destination, "user@server2.com");
        assert_eq!(result.targets.len(), 2);
        assert!(result.targets.contains(&"x86_64-unknown-linux-gnu".to_string()));
        assert!(result.targets.contains(&"aarch64-unknown-linux-gnu".to_string()));

        // Verify the config string was updated correctly
        assert!(config_str.contains("aarch64-unknown-linux-gnu"));
    }

    #[test]
    fn test_upsert_with_add_new_host() {
        let mut config_str = String::from(
            r#"{
  "host": [
    {
      "destination": "user@server1.com",
      "targets": ["aarch64-apple-darwin"]
    }
  ]
}"#,
        );

        // Add a completely new host
        let result = upsert_with(&mut config_str, "x86_64-unknown-linux-gnu", |hosts| {
            assert_eq!(hosts.len(), 1);
            Ok(UserResponse::AddNewHost {
                destination: "user@newserver.com".to_string(),
            })
        })
        .expect("test should succeed");

        assert_eq!(result.destination, "user@newserver.com");
        assert_eq!(result.targets.len(), 1);
        assert!(result.targets.contains(&"x86_64-unknown-linux-gnu".to_string()));

        // Verify both hosts exist in the config
        assert!(config_str.contains("user@server1.com"));
        assert!(config_str.contains("user@newserver.com"));
        assert!(config_str.contains("x86_64-unknown-linux-gnu"));

        // Verify structure
        let config: ConfigFile = serde_json::from_str(&config_str).unwrap();
        assert_eq!(config.host.len(), 2);
    }

    #[test]
    fn test_upsert_with_empty_config_add_first_host() {
        let mut config_str = String::from(r#"{"host": []}"#);

        let result = upsert_with(&mut config_str, "aarch64-apple-darwin", |hosts| {
            assert_eq!(hosts.len(), 0);
            Ok(UserResponse::AddNewHost {
                destination: "user@firsthost.com".to_string(),
            })
        })
        .expect("test should succeed");

        assert_eq!(result.destination, "user@firsthost.com");
        assert_eq!(result.targets, vec!["aarch64-apple-darwin".to_string()]);

        // Verify the new host was added
        assert!(config_str.contains("user@firsthost.com"));
        assert!(config_str.contains("aarch64-apple-darwin"));
    }

    #[test]
    fn test_upsert_with_completely_empty_string() {
        let mut config_str = String::from("");

        let result = upsert_with(&mut config_str, "aarch64-apple-darwin", |hosts| {
            assert_eq!(hosts.len(), 0);
            Ok(UserResponse::AddNewHost {
                destination: "user@firsthost.com".to_string(),
            })
        })
        .expect("test should succeed");

        assert_eq!(result.destination, "user@firsthost.com");
        assert_eq!(result.targets, vec!["aarch64-apple-darwin".to_string()]);

        // Verify the new host was added
        assert!(config_str.contains("user@firsthost.com"));
        assert!(config_str.contains("aarch64-apple-darwin"));
    }

    #[test]
    fn test_upsert_with_multiple_targets_in_result() {
        let mut config_str = String::from(
            r#"{
  "host": [
    {
      "destination": "user@server1.com",
      "targets": ["aarch64-apple-darwin", "x86_64-apple-darwin", "aarch64-unknown-linux-gnu"]
    }
  ]
}"#,
        );

        // Find existing host with multiple targets
        let result = upsert_with(&mut config_str, "aarch64-unknown-linux-gnu", |_hosts| {
            panic!("Should not be called");
        })
        .expect("test should succeed");

        assert_eq!(result.destination, "user@server1.com");
        assert_eq!(result.targets.len(), 3);
    }

    // Error test cases

    #[test]
    fn test_error_malformed_json() {
        let mut config_str = String::from(
            r#"{"host": [{"destination": "server1", "targets": ["target1""#,
        ); // Missing closing brackets

        let result = upsert_with(&mut config_str, "new-target", |_hosts| {
            panic!("Should not be called");
        });

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to parse JSON"));
    }

    #[test]
    fn test_error_host_not_array() {
        let mut config_str = String::from(r#"{"host": "not an array"}"#);

        let result = upsert_with(&mut config_str, "target", |_hosts| {
            panic!("Should not be called");
        });

        assert!(result.is_err());
        // serde_json will provide a descriptive error about type mismatch
    }

    #[test]
    fn test_error_invalid_host_index() {
        let mut config_str = String::from(
            r#"{
  "host": [
    {
      "destination": "user@server1.com",
      "targets": ["aarch64-apple-darwin"]
    }
  ]
}"#,
        );

        let result = upsert_with(&mut config_str, "new-target", |_hosts| {
            Ok(UserResponse::AddTargetToHost { host_index: 999 })
        });

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Invalid host_index"));
    }

    #[test]
    fn test_upsert_with_add_new_host_merges_existing_destination() {
        let mut config_str = String::from(
            r#"{
  "host": [
    {
      "destination": "user@server1.com",
      "targets": ["aarch64-apple-darwin"]
    }
  ]
}"#,
        );

        // User adds a new host with same destination as existing
        let result = upsert_with(&mut config_str, "x86_64-unknown-linux-gnu", |hosts| {
            assert_eq!(hosts.len(), 1);
            Ok(UserResponse::AddNewHost {
                destination: "user@server1.com".to_string(), // Same as existing
            })
        })
        .expect("test should succeed");

        // Should merge into existing host, not create duplicate
        assert_eq!(result.destination, "user@server1.com");
        assert_eq!(result.targets.len(), 2);
        assert!(result.targets.contains(&"aarch64-apple-darwin".to_string()));
        assert!(result.targets.contains(&"x86_64-unknown-linux-gnu".to_string()));

        // Verify only one host exists
        let config: ConfigFile = serde_json::from_str(&config_str).unwrap();
        assert_eq!(config.host.len(), 1);
    }
}
