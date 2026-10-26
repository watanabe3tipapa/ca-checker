use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CertSource {
    OsTrustStore,
    File(PathBuf),
    Network { host: String, port: u16 },
}

impl CertSource {
    pub fn label(&self) -> String {
        match self {
            CertSource::OsTrustStore => "OS trust store".to_string(),
            CertSource::File(path) => path.display().to_string(),
            CertSource::Network { host, port } => format!("{host}:{port}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidationStatus {
    Valid,
    ExpiringSoon,
    Expired,
    NotYetValid,
    UntrustedRoot,
    SelfSigned,
    WeakSignature,
    RevocationUnknown,
    Error(String),
}

impl ValidationStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(
            self,
            ValidationStatus::Valid | ValidationStatus::ExpiringSoon
        )
    }

    pub fn label(&self) -> &'static str {
        match self {
            ValidationStatus::Valid => "Valid",
            ValidationStatus::ExpiringSoon => "Expiring soon",
            ValidationStatus::Expired => "Expired",
            ValidationStatus::NotYetValid => "Not yet valid",
            ValidationStatus::UntrustedRoot => "Untrusted root",
            ValidationStatus::SelfSigned => "Self-signed",
            ValidationStatus::WeakSignature => "Weak signature",
            ValidationStatus::RevocationUnknown => "Revocation unknown",
            ValidationStatus::Error(_) => "Error",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub source: CertSource,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub san: Vec<String>,
    pub signature_algorithm: String,
    pub key_algorithm: String,
    pub is_ca: bool,
    pub path_length: Option<u32>,
    pub raw_der: Vec<u8>,
    pub fingerprint_sha256: String,
}

impl Certificate {
    pub fn days_until_expiry(&self, now: DateTime<Utc>) -> i64 {
        (self.not_after - now).num_days()
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now > self.not_after
    }

    pub fn is_not_yet_valid(&self, now: DateTime<Utc>) -> bool {
        now < self.not_before
    }

    pub fn is_self_issued(&self) -> bool {
        self.subject == self.issuer
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainValidationResult {
    pub target: Certificate,
    pub intermediates: Vec<Certificate>,
    pub trust_anchor: Option<Certificate>,
    pub status: ValidationStatus,
    pub checked_at: DateTime<Utc>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}
