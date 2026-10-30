pub mod config;
pub mod file_loader;
pub mod network;
pub mod notify;
pub mod os_store;
pub mod revocation;

use std::path::PathBuf;

pub use config::{
    AppConfig, ConfigError, NotificationConfig, RevocationConfig, RevocationMode, config_path,
};
pub use file_loader::{ScanResult, load_directory, load_file, load_path};
pub use network::{FetchedChain, fetch_chain};
pub use notify::{NotificationSummary, notify_summary, send_desktop_notification};
pub use os_store::{OsStoreResult, load_os_store};
pub use revocation::{RevocationCache, RevocationCheck, check_revocation};

#[derive(Debug, thiserror::Error)]
pub enum InfraError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Parse(#[from] cert_core::ParseError),
    #[error("no certificates found in {0}")]
    NoCertificates(PathBuf),
    #[error("native certificate store error: {0}")]
    NativeStore(String),
    #[error("invalid server name: {0}")]
    InvalidServerName(String),
    #[error("network error while fetching certificates from {host}:{port}: {message}")]
    Network {
        host: String,
        port: u16,
        message: String,
    },
    #[error("no certificates presented by {host}:{port}")]
    NoCertificatesFromPeer { host: String, port: u16 },
    #[error("network certificate fetching is not implemented yet")]
    NetworkUnsupported,
    #[error("revocation check failed: {0}")]
    Revocation(String),
    #[error("desktop notification failed: {0}")]
    Notification(String),
}

pub fn trust_anchors_der(certificates: &[cert_core::Certificate]) -> Vec<Vec<u8>> {
    certificates
        .iter()
        .map(|certificate| certificate.raw_der.clone())
        .collect()
}
