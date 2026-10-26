pub mod file_loader;
pub mod network;
pub mod os_store;

use std::path::PathBuf;

pub use file_loader::{ScanResult, load_directory, load_file, load_path};
pub use os_store::{OsStoreResult, load_os_store};

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
    #[error("network certificate fetching is not implemented yet")]
    NetworkUnsupported,
}

pub fn trust_anchors_der(certificates: &[cert_core::Certificate]) -> Vec<Vec<u8>> {
    certificates
        .iter()
        .map(|certificate| certificate.raw_der.clone())
        .collect()
}
