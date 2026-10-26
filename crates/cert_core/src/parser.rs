use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr};

use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;
use x509_parser::time::ASN1Time;

use crate::models::{CertSource, Certificate};

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("no certificate found in input")]
    Empty,
    #[error("PEM parse failed: {0}")]
    Pem(String),
    #[error("X.509 parse failed: {0}")]
    X509(String),
    #[error("invalid timestamp in certificate")]
    Timestamp,
}

pub fn parse_certificates(
    bytes: &[u8],
    source: CertSource,
) -> Result<Vec<Certificate>, ParseError> {
    if bytes.windows(10).any(|window| window == b"-----BEGIN") {
        parse_pem_certificates(bytes, source)
    } else {
        let cert = parse_der_certificate(bytes, source)?;
        Ok(vec![cert])
    }
}

pub fn parse_pem_certificates(
    bytes: &[u8],
    source: CertSource,
) -> Result<Vec<Certificate>, ParseError> {
    let mut remaining = bytes;
    let mut certificates = Vec::new();
    let mut last_error = None;

    while !remaining.is_empty() {
        let trimmed = trim_ascii_start(remaining);
        if trimmed.is_empty() {
            break;
        }

        match parse_x509_pem(trimmed) {
            Ok((rest, pem)) => {
                match parse_der_certificate(&pem.contents, source.clone()) {
                    Ok(cert) => certificates.push(cert),
                    Err(err) => last_error = Some(err),
                }
                remaining = rest;
            }
            Err(err) => {
                last_error = Some(ParseError::Pem(err.to_string()));
                break;
            }
        }
    }

    if certificates.is_empty() {
        return Err(last_error.unwrap_or(ParseError::Empty));
    }

    Ok(certificates)
}

pub fn parse_der_certificate(der: &[u8], source: CertSource) -> Result<Certificate, ParseError> {
    let (_, x509) =
        X509Certificate::from_der(der).map_err(|err| ParseError::X509(err.to_string()))?;
    certificate_from_x509(&x509, der.to_vec(), source)
}

fn certificate_from_x509(
    x509: &X509Certificate<'_>,
    raw_der: Vec<u8>,
    source: CertSource,
) -> Result<Certificate, ParseError> {
    let mut san = Vec::new();
    let mut is_ca = false;
    let mut path_length = None;

    for extension in x509.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(names) => {
                san = names
                    .general_names
                    .iter()
                    .map(format_general_name)
                    .collect();
            }
            ParsedExtension::BasicConstraints(basic_constraints) => {
                is_ca = basic_constraints.ca;
                path_length = basic_constraints.path_len_constraint;
            }
            _ => {}
        }
    }

    Ok(Certificate {
        source,
        subject: x509.subject().to_string(),
        issuer: x509.issuer().to_string(),
        serial: x509.tbs_certificate.raw_serial_as_string(),
        not_before: to_utc(&x509.validity().not_before)?,
        not_after: to_utc(&x509.validity().not_after)?,
        san,
        signature_algorithm: x509.signature_algorithm.algorithm.to_id_string(),
        key_algorithm: x509.public_key().algorithm.algorithm.to_id_string(),
        is_ca,
        path_length,
        fingerprint_sha256: fingerprint_sha256(&raw_der),
        raw_der,
    })
}

fn to_utc(time: &ASN1Time) -> Result<DateTime<Utc>, ParseError> {
    DateTime::from_timestamp(time.timestamp(), 0).ok_or(ParseError::Timestamp)
}

fn format_general_name(name: &GeneralName<'_>) -> String {
    match name {
        GeneralName::DNSName(value) => (*value).to_string(),
        GeneralName::RFC822Name(value) => (*value).to_string(),
        GeneralName::URI(value) => (*value).to_string(),
        GeneralName::IPAddress(bytes) => match bytes.len() {
            4 => Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
            16 => {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(bytes);
                Ipv6Addr::from(octets).to_string()
            }
            _ => format!("ip:{bytes:?}"),
        },
        GeneralName::DirectoryName(value) => value.to_string(),
        GeneralName::RegisteredID(oid) => oid.to_id_string(),
        GeneralName::OtherName(oid, _) => format!("otherName:{}", oid.to_id_string()),
        GeneralName::X400Address(_) => "x400Address".to_string(),
        GeneralName::EDIPartyName(_) => "ediPartyName".to_string(),
        GeneralName::Invalid(_, _) => "invalid".to_string(),
    }
}

fn trim_ascii_start(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn fingerprint_sha256(der: &[u8]) -> String {
    use std::fmt::Write;

    let digest = Sha256::digest(der);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
