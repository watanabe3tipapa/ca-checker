use std::time::Duration;

use chrono::{DateTime, Utc};
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::models::{
    CertSource, Certificate, ChainValidationResult, RevocationCheck, RevocationStatus,
    ValidationStatus,
};
use crate::parser::parse_der_certificate;

const WEAK_SIGNATURE_OIDS: &[&str] = &[
    "1.2.840.113549.1.1.4",
    "1.2.840.113549.1.1.5",
    "1.2.840.10045.4.1",
    "1.2.840.10040.4.3",
];

pub struct ValidationOptions {
    pub now: DateTime<Utc>,
    pub warn_days: i64,
}

impl Default for ValidationOptions {
    fn default() -> Self {
        Self {
            now: Utc::now(),
            warn_days: 30,
        }
    }
}

pub fn validate(
    target: &Certificate,
    intermediates: &[Certificate],
    trust_anchors_der: &[Vec<u8>],
    options: &ValidationOptions,
) -> ChainValidationResult {
    let now = options.now;
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut status;
    let mut trust_anchor = None;

    if target.is_not_yet_valid(now) {
        status = ValidationStatus::NotYetValid;
        errors.push(format!(
            "certificate is not valid before {}",
            target.not_before
        ));
    } else if target.is_expired(now) {
        status = ValidationStatus::Expired;
        errors.push(format!("certificate expired at {}", target.not_after));
    } else if is_weak_signature(&target.signature_algorithm) {
        status = ValidationStatus::WeakSignature;
        errors.push(format!(
            "signature algorithm is considered weak: {}",
            target.signature_algorithm
        ));
    } else if trust_anchors_der
        .iter()
        .any(|anchor| anchor.as_slice() == target.raw_der.as_slice())
    {
        status = expiry_status(target, options);
    } else if target.is_self_issued() {
        status = ValidationStatus::SelfSigned;
        errors.push("certificate is self-signed and not present in the trust store".to_string());
    } else {
        match verify_chain(target, intermediates, trust_anchors_der, options) {
            Ok(anchor) => {
                status = expiry_status(target, options);
                trust_anchor = anchor;
            }
            Err(err) => {
                status = match &err {
                    webpki::Error::UnknownIssuer => ValidationStatus::UntrustedRoot,
                    webpki::Error::CertExpired { .. } => ValidationStatus::Expired,
                    webpki::Error::CertNotValidYet { .. } => ValidationStatus::NotYetValid,
                    other => ValidationStatus::Error(other.to_string()),
                };
                errors.push(format!("chain validation failed: {err}"));
            }
        }
    }

    if status == ValidationStatus::Valid {
        let days = target.days_until_expiry(now);
        if (0..=options.warn_days).contains(&days) {
            status = ValidationStatus::ExpiringSoon;
            warnings.push(format!("certificate expires in {days} day(s)"));
        }
    }

    if target.is_ca && target.path_length.is_none() {
        warnings.push("CA certificate has no path length constraint".to_string());
    }
    if target.san.is_empty() && !target.is_ca {
        warnings.push("leaf certificate has no subject alternative names".to_string());
    }

    ChainValidationResult {
        target: target.clone(),
        intermediates: intermediates.to_vec(),
        trust_anchor,
        status,
        checked_at: now,
        errors,
        warnings,
        revocation: None,
    }
}

pub fn validate_in_os_store(
    target: &Certificate,
    trust_anchors_der: &[Vec<u8>],
    options: &ValidationOptions,
) -> ChainValidationResult {
    validate(target, &[], trust_anchors_der, options)
}

pub fn apply_revocation(result: &mut ChainValidationResult, check: &RevocationCheck) {
    result.revocation = Some(check.clone());
    match &check.status {
        RevocationStatus::Revoked { reason, revoked_at } => {
            let mut message = format!("certificate is revoked ({})", check.source);
            if let Some(reason) = reason {
                message.push_str(&format!(": {reason}"));
            }
            if let Some(revoked_at) = revoked_at {
                message.push_str(&format!(" at {revoked_at}"));
            }
            result.errors.push(message);
            result.status = ValidationStatus::Revoked;
        }
        RevocationStatus::Unknown { message } => {
            result.warnings.push(format!(
                "revocation status is unknown ({}): {message}",
                check.source
            ));
            if result.status.is_healthy() {
                result.status = ValidationStatus::RevocationUnknown;
            }
        }
        RevocationStatus::Good => {
            result
                .warnings
                .push(format!("revocation status is good ({})", check.source));
        }
    }
}

fn expiry_status(target: &Certificate, options: &ValidationOptions) -> ValidationStatus {
    let days = target.days_until_expiry(options.now);
    if (0..=options.warn_days).contains(&days) {
        ValidationStatus::ExpiringSoon
    } else {
        ValidationStatus::Valid
    }
}

fn verify_chain(
    target: &Certificate,
    intermediates: &[Certificate],
    trust_anchors_der: &[Vec<u8>],
    options: &ValidationOptions,
) -> Result<Option<Certificate>, webpki::Error> {
    if trust_anchors_der.is_empty() {
        return Err(webpki::Error::UnknownIssuer);
    }

    let end_entity_der = CertificateDer::from(target.raw_der.as_slice());
    let end_entity = webpki::EndEntityCert::try_from(&end_entity_der)?;

    let intermediate_der: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|cert| CertificateDer::from(cert.raw_der.as_slice()))
        .collect();

    let anchor_der: Vec<CertificateDer<'_>> = trust_anchors_der
        .iter()
        .map(|der| CertificateDer::from(der.as_slice()))
        .collect();
    let anchors: Vec<TrustAnchor<'_>> = anchor_der
        .iter()
        .filter_map(|der| webpki::anchor_from_trusted_cert(der).ok())
        .collect();

    let time =
        UnixTime::since_unix_epoch(Duration::from_secs(options.now.timestamp().max(0) as u64));

    let verified = end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediate_der,
            time,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .or_else(|err| match is_eku_error(&err) {
            true => end_entity.verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &anchors,
                &intermediate_der,
                time,
                webpki::KeyUsage::client_auth(),
                None,
                None,
            ),
            false => Err(err),
        })?;

    let anchor_spki = verified.anchor().subject_public_key_info.as_ref();
    Ok(find_anchor_certificate(anchor_spki, trust_anchors_der))
}

fn is_eku_error(error: &webpki::Error) -> bool {
    matches!(error, webpki::Error::RequiredEkuNotFoundContext(_))
}

fn find_anchor_certificate(
    anchor_spki: &[u8],
    trust_anchors_der: &[Vec<u8>],
) -> Option<Certificate> {
    trust_anchors_der.iter().find_map(|der| {
        let (_, x509) = X509Certificate::from_der(der).ok()?;
        if der_content(x509.tbs_certificate.subject_pki.raw) != Some(anchor_spki) {
            return None;
        }
        parse_der_certificate(der, CertSource::OsTrustStore).ok()
    })
}

fn der_content(der: &[u8]) -> Option<&[u8]> {
    let length_byte = *der.get(1)?;
    let header_length = if length_byte & 0x80 == 0 {
        2
    } else {
        let length_bytes = usize::from(length_byte & 0x7f);
        if length_bytes == 0 || der.len() < 2 + length_bytes {
            return None;
        }
        2 + length_bytes
    };
    der.get(header_length..)
}

pub fn is_weak_signature(algorithm: &str) -> bool {
    let lower = algorithm.to_ascii_lowercase();
    WEAK_SIGNATURE_OIDS.contains(&algorithm)
        || lower.contains("md5")
        || lower.contains("sha1")
        || lower.contains("sha-1")
}
