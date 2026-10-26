use cert_core::{CertSource, Certificate, parse_der_certificate};

use crate::InfraError;

#[derive(Debug, Default)]
pub struct OsStoreResult {
    pub certificates: Vec<Certificate>,
    pub errors: Vec<String>,
}

pub fn load_os_store() -> Result<OsStoreResult, InfraError> {
    let native = rustls_native_certs::load_native_certs();
    let mut result = OsStoreResult {
        certificates: Vec::with_capacity(native.certs.len()),
        errors: native
            .errors
            .iter()
            .map(|error| error.to_string())
            .collect(),
    };

    for der in native.certs {
        match parse_der_certificate(der.as_ref(), CertSource::OsTrustStore) {
            Ok(certificate) => result.certificates.push(certificate),
            Err(err) => result.errors.push(err.to_string()),
        }
    }

    result
        .certificates
        .sort_by(|left, right| left.subject.cmp(&right.subject));
    Ok(result)
}
