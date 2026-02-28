use serde::Serialize;
use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    Usage,
    Auth,
    Sync,
    Crypto,
    Io,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    Usage = 2,
    Auth = 3,
    Sync = 4,
    Crypto = 5,
    Io = 6,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

#[derive(Debug, thiserror::Error, Serialize)]
#[error("{message}")]
pub struct InkError {
    pub kind: ErrorKind,
    pub message: String,
}

impl InkError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Usage, message)
    }

    pub fn auth(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Auth, message)
    }

    pub fn sync(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Sync, message)
    }

    pub fn crypto(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Crypto, message)
    }

    pub fn io(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Io, message)
    }

    pub fn unimplemented(feature: impl Into<String>) -> Self {
        Self::usage(format!("not implemented yet: {}", feature.into()))
    }

    pub fn exit_code(&self) -> ExitCode {
        match self.kind {
            ErrorKind::Usage => ExitCode::Usage,
            ErrorKind::Auth => ExitCode::Auth,
            ErrorKind::Sync => ExitCode::Sync,
            ErrorKind::Crypto => ExitCode::Crypto,
            ErrorKind::Io => ExitCode::Io,
        }
    }
}

impl From<std::io::Error> for InkError {
    fn from(value: std::io::Error) -> Self {
        Self::io(value.to_string())
    }
}

impl From<&str> for InkError {
    fn from(value: &str) -> Self {
        Self::usage(value)
    }
}

impl From<String> for InkError {
    fn from(value: String) -> Self {
        Self::usage(value)
    }
}

impl<T: Display> From<(ErrorKind, T)> for InkError {
    fn from((kind, value): (ErrorKind, T)) -> Self {
        Self::new(kind, value.to_string())
    }
}

pub type InkResult<T> = Result<T, InkError>;
