use chrono::{DateTime, Utc};
use der::{Decode, Encode};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_cert::Certificate as X509Cert;
use x509_ocsp::builder::OcspRequestBuilder;
use x509_ocsp::{
    BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, Request, ResponderId,
};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;

use crate::models::{Certificate, RevocationCheck, RevocationStatus};

#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    #[error("issuer certificate could not be found")]
    IssuerNotFound,
    #[error("certificate has no CRL distribution point")]
    NoCrlDistributionPoint,
    #[error("certificate has no OCSP responder")]
    NoOcspResponder,
    #[error("failed to parse revocation data: {0}")]
    Parse(String),
    #[error("revocation signature verification failed: {0}")]
    Signature(String),
    #[error("revocation data is stale: {0}")]
    Stale(String),
    #[error("OCSP responder returned an error: {0}")]
    OcspStatus(String),
    #[error("OCSP response does not contain this certificate")]
    MissingResponse,
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

pub fn find_issuer_certificate<'a>(
    target: &Certificate,
    intermediates: &'a [Certificate],
    anchors: &'a [Certificate],
) -> Option<&'a Certificate> {
    intermediates
        .iter()
        .chain(anchors.iter())
        .find(|candidate| candidate.subject == target.issuer && is_signed_by(target, candidate))
        .or_else(|| {
            intermediates
                .iter()
                .chain(anchors.iter())
                .find(|candidate| candidate.subject == target.issuer)
        })
}

fn is_signed_by(target: &Certificate, issuer: &Certificate) -> bool {
    let Ok((_, target_x509)) = X509Certificate::from_der(&target.raw_der) else {
        return false;
    };
    let Ok((_, issuer_x509)) = X509Certificate::from_der(&issuer.raw_der) else {
        return false;
    };
    target_x509
        .verify_signature(Some(issuer_x509.public_key()))
        .is_ok()
}

pub fn build_ocsp_request(
    target: &Certificate,
    issuer: &Certificate,
) -> Result<Vec<u8>, RevocationError> {
    let issuer_cert = X509Cert::from_der(&issuer.raw_der)
        .map_err(|err| RevocationError::Parse(err.to_string()))?;
    let target_cert = X509Cert::from_der(&target.raw_der)
        .map_err(|err| RevocationError::Parse(err.to_string()))?;
    let request = OcspRequestBuilder::default()
        .with_request(
            Request::from_cert::<Sha256>(&issuer_cert, &target_cert)
                .map_err(|err| RevocationError::Parse(err.to_string()))?,
        )
        .build();
    request
        .to_der()
        .map_err(|err| RevocationError::Parse(err.to_string()))
}

pub fn check_crl(
    target: &Certificate,
    issuer: &Certificate,
    crl_der: &[u8],
    now: DateTime<Utc>,
    source: &str,
) -> Result<RevocationCheck, RevocationError> {
    let (_, crl) = CertificateRevocationList::from_der(crl_der)
        .map_err(|err| RevocationError::Parse(err.to_string()))?;
    let (_, issuer_x509) = X509Certificate::from_der(&issuer.raw_der)
        .map_err(|err| RevocationError::Parse(err.to_string()))?;

    if crl.issuer().to_string() != issuer.subject {
        return Err(RevocationError::Signature(format!(
            "CRL issuer {} does not match certificate issuer {}",
            crl.issuer(),
            issuer.subject
        )));
    }

    crl.verify_signature(issuer_x509.public_key())
        .map_err(|err| RevocationError::Signature(err.to_string()))?;

    if crl.last_update().timestamp() > now.timestamp() {
        return Err(RevocationError::Stale(format!(
            "CRL is not valid before {}",
            crl.last_update()
        )));
    }
    if let Some(next_update) = crl.next_update() {
        if next_update.timestamp() < now.timestamp() {
            return Err(RevocationError::Stale(format!(
                "CRL expired at {}",
                next_update
            )));
        }
    }

    let (_, target_x509) = X509Certificate::from_der(&target.raw_der)
        .map_err(|err| RevocationError::Parse(err.to_string()))?;
    let serial = target_x509.tbs_certificate.raw_serial();

    let revoked = crl
        .iter_revoked_certificates()
        .find(|entry| entry.raw_serial() == serial);

    let status = match revoked {
        Some(entry) => RevocationStatus::Revoked {
            reason: entry.reason_code().map(|(_, reason)| format!("{reason:?}")),
            revoked_at: DateTime::from_timestamp(entry.revocation_date.timestamp(), 0),
        },
        None => RevocationStatus::Good,
    };

    Ok(RevocationCheck {
        status,
        source: source.to_string(),
        checked_at: now,
        details: vec![format!(
            "CRL last update {} · next update {}",
            crl.last_update(),
            crl.next_update()
                .map(|time| time.to_string())
                .unwrap_or_else(|| "-".to_string())
        )],
    })
}

pub fn check_ocsp(
    target: &Certificate,
    issuer: &Certificate,
    response_der: &[u8],
    now: DateTime<Utc>,
    source: &str,
) -> Result<RevocationCheck, RevocationError> {
    let response = OcspResponse::from_der(response_der)
        .map_err(|err| RevocationError::Parse(err.to_string()))?;
    if response.response_status != OcspResponseStatus::Successful {
        return Err(RevocationError::OcspStatus(format!(
            "{:?}",
            response.response_status
        )));
    }

    let response_bytes = response
        .response_bytes
        .ok_or_else(|| RevocationError::Parse("missing response bytes".to_string()))?;
    if response_bytes.response_type.to_string() != "1.3.6.1.5.5.7.48.1.1" {
        return Err(RevocationError::Parse(format!(
            "unsupported OCSP response type {}",
            response_bytes.response_type
        )));
    }

    let basic = BasicOcspResponse::from_der(response_bytes.response.as_bytes())
        .map_err(|err| RevocationError::Parse(err.to_string()))?;

    let issuer_cert = X509Cert::from_der(&issuer.raw_der)
        .map_err(|err| RevocationError::Parse(err.to_string()))?;
    let target_cert = X509Cert::from_der(&target.raw_der)
        .map_err(|err| RevocationError::Parse(err.to_string()))?;

    let responder = select_responder(&basic, &issuer_cert)?;
    verify_responder(&responder, &issuer_cert, &basic)?;

    let tbs = basic
        .tbs_response_data
        .to_der()
        .map_err(|err| RevocationError::Parse(err.to_string()))?;
    let signature = basic
        .signature
        .as_bytes()
        .ok_or_else(|| RevocationError::Parse("invalid OCSP signature".to_string()))?;
    verify_signature(
        &responder.tbs_certificate.subject_public_key_info,
        &basic.signature_algorithm.oid.to_string(),
        &tbs,
        signature,
    )?;

    check_ocsp_freshness(&basic, now)?;

    let single = basic
        .tbs_response_data
        .responses
        .iter()
        .find(|entry| entry.cert_id.serial_number == target_cert.tbs_certificate.serial_number)
        .ok_or(RevocationError::MissingResponse)?;

    verify_cert_id(&single.cert_id, &issuer_cert)?;

    let status = match single.cert_status {
        CertStatus::Good(_) => RevocationStatus::Good,
        CertStatus::Revoked(info) => RevocationStatus::Revoked {
            reason: info.revocation_reason.map(|reason| format!("{reason:?}")),
            revoked_at: DateTime::from_timestamp(
                info.revocation_time
                    .as_ref()
                    .to_date_time()
                    .unix_duration()
                    .as_secs() as i64,
                0,
            ),
        },
        CertStatus::Unknown(_) => RevocationStatus::Unknown {
            message: "responder returned unknown status".to_string(),
        },
    };

    Ok(RevocationCheck {
        status,
        source: source.to_string(),
        checked_at: now,
        details: vec![format!(
            "this update {} · next update {}",
            single.this_update.as_ref().to_date_time(),
            single
                .next_update
                .map(|time| time.as_ref().to_date_time().to_string())
                .unwrap_or_else(|| "-".to_string())
        )],
    })
}

fn select_responder(
    basic: &BasicOcspResponse,
    issuer: &X509Cert,
) -> Result<X509Cert, RevocationError> {
    if let Some(certs) = &basic.certs {
        if let Some(cert) = certs
            .iter()
            .find(|cert| responder_id_matches(&basic.tbs_response_data.responder_id, cert))
        {
            return Ok(cert.clone());
        }
        if let Some(cert) = certs.first() {
            return Ok(cert.clone());
        }
    }
    Ok(issuer.clone())
}

fn responder_id_matches(id: &ResponderId, cert: &X509Cert) -> bool {
    match id {
        ResponderId::ByName(name) => name == &cert.tbs_certificate.subject,
        ResponderId::ByKey(key_hash) => {
            let spki = &cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key;
            let digest = Sha1::digest(spki.raw_bytes());
            key_hash.as_bytes() == digest.as_slice()
        }
    }
}

fn verify_responder(
    responder: &X509Cert,
    issuer: &X509Cert,
    basic: &BasicOcspResponse,
) -> Result<(), RevocationError> {
    let responder_der = responder
        .to_der()
        .map_err(|err| RevocationError::Parse(err.to_string()))?;
    let issuer_der = issuer
        .to_der()
        .map_err(|err| RevocationError::Parse(err.to_string()))?;

    if responder_der == issuer_der {
        return Ok(());
    }

    let (_, responder_x509) = X509Certificate::from_der(&responder_der)
        .map_err(|err| RevocationError::Parse(err.to_string()))?;
    let (_, issuer_x509) = X509Certificate::from_der(&issuer_der)
        .map_err(|err| RevocationError::Parse(err.to_string()))?;

    responder_x509
        .verify_signature(Some(issuer_x509.public_key()))
        .map_err(|err| RevocationError::Signature(format!("responder certificate: {err}")))?;

    if !has_ocsp_signing_eku(&responder_der) {
        return Err(RevocationError::Signature(
            "responder certificate lacks the OCSP signing extended key usage".to_string(),
        ));
    }

    if !responder_id_matches(&basic.tbs_response_data.responder_id, responder) {
        return Err(RevocationError::Signature(
            "OCSP responder ID does not match the signing certificate".to_string(),
        ));
    }

    Ok(())
}

fn has_ocsp_signing_eku(cert_der: &[u8]) -> bool {
    use x509_parser::extensions::ParsedExtension;

    let Ok((_, cert)) = X509Certificate::from_der(cert_der) else {
        return false;
    };
    cert.extensions().iter().any(|extension| {
        matches!(
            extension.parsed_extension(),
            ParsedExtension::ExtendedKeyUsage(usage)
                if usage.ocsp_signing
        )
    })
}

fn check_ocsp_freshness(
    basic: &BasicOcspResponse,
    now: DateTime<Utc>,
) -> Result<(), RevocationError> {
    let now_ts = now.timestamp();
    for single in &basic.tbs_response_data.responses {
        let this_update = single
            .this_update
            .as_ref()
            .to_date_time()
            .unix_duration()
            .as_secs() as i64;
        if this_update > now_ts + 300 {
            return Err(RevocationError::Stale(format!(
                "OCSP response is not valid yet (this update {this_update})"
            )));
        }
        if let Some(next_update) = single.next_update {
            let next_update = next_update
                .as_ref()
                .to_date_time()
                .unix_duration()
                .as_secs() as i64;
            if next_update < now_ts - 300 {
                return Err(RevocationError::Stale(format!(
                    "OCSP response expired at {next_update}"
                )));
            }
        }
    }
    Ok(())
}

fn verify_cert_id(cert_id: &x509_ocsp::CertId, issuer: &X509Cert) -> Result<(), RevocationError> {
    let issuer_name = issuer
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|err| RevocationError::Parse(err.to_string()))?;
    let issuer_key = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();

    let (name_hash, key_hash) = match cert_id.hash_algorithm.oid.to_string().as_str() {
        "1.3.14.3.2.26" => (
            Sha1::digest(&issuer_name).to_vec(),
            Sha1::digest(issuer_key).to_vec(),
        ),
        "2.16.840.1.101.3.4.2.1" => (
            Sha256::digest(&issuer_name).to_vec(),
            Sha256::digest(issuer_key).to_vec(),
        ),
        "2.16.840.1.101.3.4.2.2" => (
            Sha384::digest(&issuer_name).to_vec(),
            Sha384::digest(issuer_key).to_vec(),
        ),
        "2.16.840.1.101.3.4.2.3" => (
            Sha512::digest(&issuer_name).to_vec(),
            Sha512::digest(issuer_key).to_vec(),
        ),
        other => {
            return Err(RevocationError::UnsupportedAlgorithm(other.to_string()));
        }
    };

    if cert_id.issuer_name_hash.as_bytes() != name_hash.as_slice()
        || cert_id.issuer_key_hash.as_bytes() != key_hash.as_slice()
    {
        return Err(RevocationError::Signature(
            "OCSP CertID does not match the issuer".to_string(),
        ));
    }

    Ok(())
}

fn verify_signature(
    spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
    algorithm_oid: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), RevocationError> {
    use ring::signature::{
        ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256,
        RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512, UnparsedPublicKey,
    };

    let algorithm: &dyn ring::signature::VerificationAlgorithm = match algorithm_oid {
        "1.2.840.113549.1.1.11" => &RSA_PKCS1_2048_8192_SHA256,
        "1.2.840.113549.1.1.12" => &RSA_PKCS1_2048_8192_SHA384,
        "1.2.840.113549.1.1.13" => &RSA_PKCS1_2048_8192_SHA512,
        "1.2.840.10045.4.3.2" => &ECDSA_P256_SHA256_ASN1,
        "1.2.840.10045.4.3.3" => &ECDSA_P384_SHA384_ASN1,
        "1.3.101.112" => &ED25519,
        other => {
            return Err(RevocationError::UnsupportedAlgorithm(other.to_string()));
        }
    };

    let key = spki.subject_public_key.raw_bytes();
    UnparsedPublicKey::new(algorithm, key)
        .verify(message, signature)
        .map_err(|err| RevocationError::Signature(err.to_string()))
}

pub fn revocation_target_serial(certificate: &Certificate) -> Option<Vec<u8>> {
    let (_, x509) = X509Certificate::from_der(&certificate.raw_der).ok()?;
    Some(x509.tbs_certificate.raw_serial().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CertSource;
    use crate::parser::parse_der_certificate;
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, IsCa, Issuer,
        KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
    };
    use time::{Duration, OffsetDateTime};

    fn ca_params(common_name: &str) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
    }

    fn test_material() -> (Certificate, Certificate, Issuer<'static, KeyPair>) {
        let root_key = KeyPair::generate().unwrap();
        let root_params = ca_params("Revocation Test Root CA");
        let root_raw = root_params.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::new(root_params, root_key);

        let mut leaf_params = CertificateParams::new(vec!["revoked.example".to_string()]).unwrap();
        leaf_params.serial_number = Some(SerialNumber::from(42_u64));
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_raw = leaf_params.signed_by(&leaf_key, &root_issuer).unwrap();

        let issuer =
            parse_der_certificate(root_raw.der(), CertSource::File("issuer.pem".into())).unwrap();
        let target =
            parse_der_certificate(leaf_raw.der(), CertSource::File("leaf.pem".into())).unwrap();
        (issuer, target, root_issuer)
    }

    #[test]
    fn crl_reports_revoked_certificate() {
        let (issuer, target, root_issuer) = test_material();
        let now = OffsetDateTime::now_utc();
        let crl = CertificateRevocationListParams {
            this_update: now - Duration::minutes(5),
            next_update: now + Duration::days(1),
            crl_number: SerialNumber::from(1_u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from(42_u64),
                revocation_time: now,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            }],
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&root_issuer)
        .unwrap();

        let check = check_crl(&target, &issuer, crl.der(), chrono::Utc::now(), "test CRL").unwrap();
        assert!(matches!(check.status, RevocationStatus::Revoked { .. }));
    }

    #[test]
    fn builds_ocsp_request_for_target() {
        let (issuer, target, _) = test_material();
        let request = build_ocsp_request(&target, &issuer).unwrap();
        let parsed = x509_ocsp::OcspRequest::from_der(&request).unwrap();
        assert_eq!(parsed.tbs_request.request_list.len(), 1);
    }

    #[test]
    fn finds_issuer_certificate() {
        let (issuer, target, _) = test_material();
        let anchors = [issuer.clone()];
        let found = find_issuer_certificate(&target, &[], &anchors).unwrap();
        assert_eq!(found.fingerprint_sha256, issuer.fingerprint_sha256);
    }

    #[test]
    fn crl_reports_good_certificate() {
        let (issuer, target, root_issuer) = test_material();
        let now = OffsetDateTime::now_utc();
        let crl = CertificateRevocationListParams {
            this_update: now - Duration::minutes(5),
            next_update: now + Duration::days(1),
            crl_number: SerialNumber::from(2_u64),
            issuing_distribution_point: None,
            revoked_certs: vec![],
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&root_issuer)
        .unwrap();

        let check = check_crl(&target, &issuer, crl.der(), chrono::Utc::now(), "test CRL").unwrap();
        assert!(matches!(check.status, RevocationStatus::Good));
    }
}
