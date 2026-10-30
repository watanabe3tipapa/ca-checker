use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write config {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("failed to encode config: {0}")]
    Encode(#[from] toml::ser::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AppConfig {
    pub warn_days: i64,
    pub notifications: NotificationConfig,
    pub revocation: RevocationConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            warn_days: 30,
            notifications: NotificationConfig::default(),
            revocation: RevocationConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct NotificationConfig {
    pub enabled: bool,
    pub on_startup: bool,
    pub expiring: bool,
    pub expired: bool,
    pub issues: bool,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            on_startup: true,
            expiring: true,
            expired: true,
            issues: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RevocationConfig {
    pub mode: RevocationMode,
    pub timeout_secs: u64,
    pub cache_secs: u64,
}

impl Default for RevocationConfig {
    fn default() -> Self {
        Self {
            mode: RevocationMode::Off,
            timeout_secs: 8,
            cache_secs: 3600,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RevocationMode {
    #[default]
    Off,
    Crl,
    Ocsp,
    Both,
}

impl RevocationMode {
    pub const ALL: [RevocationMode; 4] = [
        RevocationMode::Off,
        RevocationMode::Crl,
        RevocationMode::Ocsp,
        RevocationMode::Both,
    ];

    pub fn label(self) -> &'static str {
        match self {
            RevocationMode::Off => "Off",
            RevocationMode::Crl => "CRL",
            RevocationMode::Ocsp => "OCSP",
            RevocationMode::Both => "CRL + OCSP",
        }
    }

    pub fn uses_crl(self) -> bool {
        matches!(self, RevocationMode::Crl | RevocationMode::Both)
    }

    pub fn uses_ocsp(self) -> bool {
        matches!(self, RevocationMode::Ocsp | RevocationMode::Both)
    }
}

impl std::str::FromStr for RevocationMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "off" | "none" | "disabled" => Ok(RevocationMode::Off),
            "crl" => Ok(RevocationMode::Crl),
            "ocsp" => Ok(RevocationMode::Ocsp),
            "both" | "all" => Ok(RevocationMode::Both),
            other => Err(format!(
                "unknown revocation mode {other:?} (expected off, crl, ocsp, or both)"
            )),
        }
    }
}

impl AppConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn load_default() -> Result<(Self, PathBuf), ConfigError> {
        let path = config_path();
        let config = Self::load(&path)?;
        Ok((config, path))
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), ConfigError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| ConfigError::Write {
                path: path.to_path_buf(),
                source,
            })?;
        }
        let contents = toml::to_string_pretty(self)?;
        fs::write(path, contents).map_err(|source| ConfigError::Write {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn example() -> &'static str {
        r#"# ca-checker configuration
warn_days = 30

[notifications]
enabled = true
on_startup = true
expiring = true
expired = true
issues = true

[revocation]
# off | crl | ocsp | both
mode = "off"
timeout_secs = 8
cache_secs = 3600
"#
    }
}

pub fn config_path() -> PathBuf {
    if let Some(path) = std::env::var_os("CA_CHECKER_CONFIG") {
        return PathBuf::from(path);
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return PathBuf::from(appdata)
                .join("ca-checker")
                .join("config.toml");
        }
    }

    if let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(config_home)
            .join("ca-checker")
            .join("config.toml");
    }

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".config").join("ca-checker").join("config.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses() {
        let config: AppConfig = toml::from_str(AppConfig::example()).unwrap();
        assert_eq!(config.warn_days, 30);
        assert!(config.notifications.enabled);
        assert_eq!(config.revocation.mode, RevocationMode::Off);
    }

    #[test]
    fn config_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let config = AppConfig {
            warn_days: 90,
            notifications: NotificationConfig {
                on_startup: false,
                ..Default::default()
            },
            revocation: RevocationConfig {
                mode: RevocationMode::Both,
                ..Default::default()
            },
        };
        config.save(&path).unwrap();

        let loaded = AppConfig::load(&path).unwrap();
        assert_eq!(loaded, config);
    }

    #[test]
    fn missing_config_returns_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let loaded = AppConfig::load(directory.path().join("missing.toml")).unwrap();
        assert_eq!(loaded, AppConfig::default());
    }
}
