use std::fs;
use std::path::Path;

use cert_core::{CertSource, Certificate, parse_certificates};

use crate::InfraError;

#[derive(Debug, Default)]
pub struct ScanResult {
    pub certificates: Vec<Certificate>,
    pub errors: Vec<String>,
}

pub fn load_path(path: impl AsRef<Path>) -> Result<Vec<Certificate>, InfraError> {
    let path = path.as_ref();
    let metadata = fs::metadata(path).map_err(|source| InfraError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    if metadata.is_dir() {
        let scan = load_directory(path)?;
        if scan.certificates.is_empty() {
            Err(InfraError::NoCertificates(path.to_path_buf()))
        } else {
            Ok(scan.certificates)
        }
    } else {
        load_file(path)
    }
}

pub fn load_file(path: impl AsRef<Path>) -> Result<Vec<Certificate>, InfraError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|source| InfraError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let certificates = parse_certificates(&bytes, CertSource::File(path.to_path_buf()))?;
    Ok(certificates)
}

pub fn load_directory(path: impl AsRef<Path>) -> Result<ScanResult, InfraError> {
    let root = path.as_ref();
    let mut result = ScanResult::default();
    let mut pending = vec![root.to_path_buf()];

    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|source| InfraError::Io {
            path: directory.clone(),
            source,
        })?;

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    result.errors.push(format!("{directory:?}: {err}"));
                    continue;
                }
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(err) => {
                    result.errors.push(format!("{}: {err}", path.display()));
                    continue;
                }
            };

            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() && is_certificate_file(&path) {
                match load_file(&path) {
                    Ok(certificates) => result.certificates.extend(certificates),
                    Err(err) => result.errors.push(format!("{}: {err}", path.display())),
                }
            }
        }
    }

    result
        .certificates
        .sort_by(|left, right| left.subject.cmp(&right.subject));
    Ok(result)
}

fn is_certificate_file(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.to_ascii_lowercase())
            .as_deref(),
        Some("pem" | "crt" | "cer" | "der")
    )
}
