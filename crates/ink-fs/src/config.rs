use crate::workspace::WorkspacePaths;
use ink_core::{InkError, InkResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;

pub const CONFIG_VERSION: u32 = 1;
pub const DEFAULT_PROFILE: &str = "default";
pub const DEFAULT_SERVER_URL: &str = "https://api.standardnotes.com";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceConfig {
    pub version: u32,
    pub active_profile: String,
    #[serde(default)]
    pub profiles: BTreeMap<String, ProfileConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub server: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileView {
    pub name: String,
    pub active: bool,
    pub server: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedProfile {
    pub name: String,
    pub server: String,
}

impl WorkspaceConfig {
    pub fn with_default_server(server: impl Into<String>) -> Self {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            DEFAULT_PROFILE.to_string(),
            ProfileConfig {
                server: server.into(),
            },
        );

        Self {
            version: CONFIG_VERSION,
            active_profile: DEFAULT_PROFILE.to_string(),
            profiles,
        }
    }

    pub fn ensure_defaults(&mut self) {
        if self.version == 0 {
            self.version = CONFIG_VERSION;
        }

        if self.profiles.is_empty() {
            self.profiles.insert(
                DEFAULT_PROFILE.to_string(),
                ProfileConfig {
                    server: DEFAULT_SERVER_URL.to_string(),
                },
            );
        }

        if self.active_profile.is_empty() {
            self.active_profile = DEFAULT_PROFILE.to_string();
        }

        if !self.profiles.contains_key(&self.active_profile) {
            if let Some(first_profile) = self.profiles.keys().next() {
                self.active_profile = first_profile.clone();
            } else {
                self.active_profile = DEFAULT_PROFILE.to_string();
                self.profiles.insert(
                    DEFAULT_PROFILE.to_string(),
                    ProfileConfig {
                        server: DEFAULT_SERVER_URL.to_string(),
                    },
                );
            }
        }
    }
}

pub fn load_config(paths: &WorkspacePaths) -> InkResult<WorkspaceConfig> {
    let contents = fs::read_to_string(&paths.config_path).map_err(|err| {
        InkError::io(format!(
            "failed to read workspace config '{}': {}",
            paths.config_path.display(),
            err
        ))
    })?;

    let mut config: WorkspaceConfig = toml::from_str(&contents).map_err(|err| {
        InkError::io(format!(
            "failed to parse workspace config '{}': {}",
            paths.config_path.display(),
            err
        ))
    })?;
    config.ensure_defaults();
    Ok(config)
}

pub fn save_config(paths: &WorkspacePaths, config: &WorkspaceConfig) -> InkResult<()> {
    let serialized = toml::to_string_pretty(config)
        .map_err(|err| InkError::io(format!("failed to encode config.toml: {err}")))?;

    fs::write(&paths.config_path, serialized).map_err(|err| {
        InkError::io(format!(
            "failed to write workspace config '{}': {}",
            paths.config_path.display(),
            err
        ))
    })
}

pub fn list_profiles(config: &WorkspaceConfig) -> Vec<ProfileView> {
    let mut profiles = Vec::with_capacity(config.profiles.len());

    for (name, profile) in &config.profiles {
        profiles.push(ProfileView {
            name: name.clone(),
            active: name == &config.active_profile,
            server: profile.server.clone(),
        });
    }

    profiles
}

pub fn set_active_profile(config: &mut WorkspaceConfig, name: &str) -> InkResult<()> {
    if !config.profiles.contains_key(name) {
        return Err(InkError::usage(format!(
            "profile '{name}' not found in workspace config"
        )));
    }

    config.active_profile = name.to_string();
    Ok(())
}

pub fn set_profile_server(config: &mut WorkspaceConfig, name: &str, server: &str) {
    config.profiles.insert(
        name.to_string(),
        ProfileConfig {
            server: server.to_string(),
        },
    );

    if config.active_profile.is_empty() {
        config.active_profile = name.to_string();
    }
}

pub fn resolve_profile(
    config: &WorkspaceConfig,
    profile_override: Option<&str>,
    server_override: Option<&str>,
) -> InkResult<ResolvedProfile> {
    let requested_profile = profile_override.unwrap_or(&config.active_profile);
    let profile = config.profiles.get(requested_profile).ok_or_else(|| {
        InkError::usage(format!(
            "profile '{requested_profile}' not found in workspace config"
        ))
    })?;

    let server = server_override
        .unwrap_or(profile.server.as_str())
        .to_string();

    Ok(ResolvedProfile {
        name: requested_profile.to_string(),
        server,
    })
}
