mod config;
mod doctor;
mod workspace;

pub use config::{
    DEFAULT_PROFILE, DEFAULT_SERVER_URL, ProfileConfig, ProfileView, ResolvedProfile,
    WorkspaceConfig, enforce_single_profile_workspace, list_profiles, load_config,
    profile_bound_email, resolve_profile, save_config, set_active_profile, set_profile_bound_email,
    set_profile_server,
};
pub use doctor::{DoctorCheck, DoctorReport, run_doctor};
pub use workspace::{WorkspaceInitResult, WorkspacePaths, init_workspace, resolve_workspace};
