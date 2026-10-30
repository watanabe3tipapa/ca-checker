use cert_core::{
    CertSource, Certificate, ValidationOptions, ValidationStatus, is_weak_signature,
    parse_certificates, parse_der_certificate, validate,
};
use chrono::Utc;
use rcgen::{
    BasicConstraints, Certificate as RcgenCertificate, CertificateParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};

struct Chain {
    root: Certificate,
    intermediate: Certificate,
    leaf: Certificate,
}

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

fn leaf_params(
    common_name: &str,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> CertificateParams {
    let mut params = CertificateParams::new(vec![common_name.to_string()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.not_before = not_before;
    params.not_after = not_after;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
}

fn build_chain(leaf_not_before: OffsetDateTime, leaf_not_after: OffsetDateTime) -> Chain {
    let root_key = KeyPair::generate().unwrap();
    let root_params = ca_params("Test Root CA");
    let root_raw = root_params.self_signed(&root_key).unwrap();
    let root_issuer = Issuer::new(root_params, root_key);

    let intermediate_key = KeyPair::generate().unwrap();
    let intermediate_params = ca_params("Test Intermediate CA");
    let intermediate_raw = intermediate_params
        .signed_by(&intermediate_key, &root_issuer)
        .unwrap();
    let intermediate_issuer = Issuer::new(intermediate_params, intermediate_key);

    let leaf_key = KeyPair::generate().unwrap();
    let leaf_raw = leaf_params("leaf.example", leaf_not_before, leaf_not_after)
        .signed_by(&leaf_key, &intermediate_issuer)
        .unwrap();

    Chain {
        root: to_certificate(&root_raw, "root.pem"),
        intermediate: to_certificate(&intermediate_raw, "intermediate.pem"),
        leaf: to_certificate(&leaf_raw, "leaf.pem"),
    }
}

fn to_certificate(certificate: &RcgenCertificate, name: &str) -> Certificate {
    parse_der_certificate(certificate.der().as_ref(), CertSource::File(name.into())).unwrap()
}

fn now_window() -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();
    (
        now.checked_sub(Duration::hours(1)).unwrap(),
        now.checked_add(Duration::days(365)).unwrap(),
    )
}

#[test]
fn parses_der_fields() {
    let (not_before, not_after) = now_window();
    let chain = build_chain(not_before, not_after);

    assert!(chain.leaf.subject.contains("leaf.example"));
    assert!(chain.leaf.issuer.contains("Test Intermediate CA"));
    assert_eq!(chain.leaf.san, vec!["leaf.example".to_string()]);
    assert!(!chain.leaf.is_ca);
    assert!(chain.root.is_ca);
    assert!(!chain.leaf.is_self_issued());
    assert_eq!(chain.leaf.fingerprint_sha256.len(), 64);
}

#[test]
fn parses_pem_certificate() {
    let (not_before, not_after) = now_window();
    let chain = build_chain(not_before, not_after);
    let key = KeyPair::generate().unwrap();
    let params = leaf_params("pem.example", not_before, not_after);
    let pem = params.self_signed(&key).unwrap().pem();

    let parsed = parse_certificates(pem.as_bytes(), CertSource::File("pem.pem".into())).unwrap();
    assert_eq!(parsed.len(), 1);
    assert!(parsed[0].subject.contains("pem.example"));
    assert!(chain.leaf.raw_der.len() > 100);
}

#[test]
fn validates_healthy_chain_against_root() {
    let (not_before, not_after) = now_window();
    let chain = build_chain(not_before, not_after);

    let result = validate(
        &chain.leaf,
        std::slice::from_ref(&chain.intermediate),
        std::slice::from_ref(&chain.root.raw_der),
        &ValidationOptions {
            now: Utc::now(),
            warn_days: 30,
        },
    );

    assert_eq!(result.status, ValidationStatus::Valid);
    assert!(result.errors.is_empty());
    assert!(result.trust_anchor.is_some());
}

#[test]
fn detects_expired_certificate() {
    let now = OffsetDateTime::now_utc();
    let chain = build_chain(
        now.checked_sub(Duration::days(365)).unwrap(),
        now.checked_sub(Duration::days(1)).unwrap(),
    );

    let result = validate(
        &chain.leaf,
        std::slice::from_ref(&chain.intermediate),
        std::slice::from_ref(&chain.root.raw_der),
        &ValidationOptions::default(),
    );

    assert_eq!(result.status, ValidationStatus::Expired);
    assert!(!result.errors.is_empty());
}

#[test]
fn detects_untrusted_root() {
    let (not_before, not_after) = now_window();
    let chain = build_chain(not_before, not_after);

    let result = validate(
        &chain.leaf,
        std::slice::from_ref(&chain.intermediate),
        &[],
        &ValidationOptions::default(),
    );

    assert_eq!(result.status, ValidationStatus::UntrustedRoot);
}

#[test]
fn detects_self_signed_certificate() {
    let (not_before, not_after) = now_window();
    let key = KeyPair::generate().unwrap();
    let raw = leaf_params("self.example", not_before, not_after)
        .self_signed(&key)
        .unwrap();
    let certificate = to_certificate(&raw, "self.pem");

    let result = validate(
        &certificate,
        &[],
        &[vec![0, 1, 2]],
        &ValidationOptions::default(),
    );

    assert_eq!(result.status, ValidationStatus::SelfSigned);
}

#[test]
fn detects_weak_signature_algorithms() {
    assert!(is_weak_signature("1.2.840.113549.1.1.5"));
    assert!(is_weak_signature("1.2.840.113549.1.1.4"));
    assert!(is_weak_signature("sha1WithRSAEncryption"));
    assert!(!is_weak_signature("1.2.840.10045.4.3.2"));
}
