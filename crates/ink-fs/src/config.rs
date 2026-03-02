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
    #[serde(default)]
    pub bound_email: Option<String>,
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
                bound_email: None,
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
                    bound_email: None,
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
                        bound_email: None,
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

pub fn enforce_single_profile_workspace(config: &WorkspaceConfig) -> InkResult<()> {
    let has_default = config.profiles.contains_key(DEFAULT_PROFILE);
    let only_default_profile = config.profiles.len() == 1 && has_default;
    let active_is_default = config.active_profile == DEFAULT_PROFILE;
    if only_default_profile && active_is_default {
        return Ok(());
    }

    let mut profile_names: Vec<&str> = config.profiles.keys().map(String::as_str).collect();
    profile_names.sort_unstable();
    let profile_summary = if profile_names.is_empty() {
        "<none>".to_string()
    } else {
        profile_names.join(", ")
    };
    Err(InkError::usage(format!(
        "workspace config is not single-profile (active='{}', profiles=[{}]); only '{}' profile is supported. Use one dedicated workspace per account/server.",
        config.active_profile, profile_summary, DEFAULT_PROFILE
    )))
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
    enforce_single_profile_workspace(config)?;
    if name != DEFAULT_PROFILE {
        return Err(InkError::usage(format!(
            "profile '{name}' is not supported; only '{}' profile is allowed per workspace. Use a dedicated workspace for each account/server.",
            DEFAULT_PROFILE
        )));
    }

    config.active_profile = DEFAULT_PROFILE.to_string();
    Ok(())
}

pub fn set_profile_server(config: &mut WorkspaceConfig, name: &str, server: &str) -> InkResult<()> {
    enforce_single_profile_workspace(config)?;
    if name != DEFAULT_PROFILE {
        return Err(InkError::usage(format!(
            "profile '{name}' is not supported; only '{}' profile is allowed per workspace. Use a dedicated workspace for each account/server.",
            DEFAULT_PROFILE
        )));
    }
    let profile = config.profiles.get_mut(DEFAULT_PROFILE).ok_or_else(|| {
        InkError::usage(format!(
            "profile '{}' not found in workspace config",
            DEFAULT_PROFILE
        ))
    })?;
    profile.server = server.to_string();
    Ok(())
}

pub fn profile_bound_email<'a>(config: &'a WorkspaceConfig, name: &str) -> Option<&'a str> {
    config
        .profiles
        .get(name)
        .and_then(|profile| profile.bound_email.as_deref())
}

pub fn set_profile_bound_email(
    config: &mut WorkspaceConfig,
    name: &str,
    email: Option<String>,
) -> InkResult<()> {
    if name != DEFAULT_PROFILE {
        return Err(InkError::usage(format!(
            "profile '{name}' is not supported; only '{}' profile is allowed per workspace. Use a dedicated workspace for each account/server.",
            DEFAULT_PROFILE
        )));
    }
    let profile = config.profiles.get_mut(name).ok_or_else(|| {
        InkError::usage(format!("profile '{name}' not found in workspace config"))
    })?;
    profile.bound_email = email;
    Ok(())
}

pub fn resolve_profile(
    config: &WorkspaceConfig,
    profile_override: Option<&str>,
    server_override: Option<&str>,
) -> InkResult<ResolvedProfile> {
    enforce_single_profile_workspace(config)?;
    if let Some(requested_profile) = profile_override
        && requested_profile != DEFAULT_PROFILE
    {
        return Err(InkError::usage(format!(
            "profile '{requested_profile}' is not supported; only '{}' profile is allowed per workspace. Use a dedicated workspace for each account/server.",
            DEFAULT_PROFILE
        )));
    }
    let profile = config.profiles.get(DEFAULT_PROFILE).ok_or_else(|| {
        InkError::usage(format!(
            "profile '{}' not found in workspace config",
            DEFAULT_PROFILE
        ))
    })?;

    let server = server_override
        .unwrap_or(profile.server.as_str())
        .to_string();

    Ok(ResolvedProfile {
        name: DEFAULT_PROFILE.to_string(),
        server,
    })
}
