use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use tempfile::TempDir;
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

fn write_chain(directory: &TempDir) -> (String, String, String) {
    let now = OffsetDateTime::now_utc();
    let not_before = now.checked_sub(Duration::hours(1)).unwrap();
    let not_after = now.checked_add(Duration::days(365)).unwrap();

    let root_key = KeyPair::generate().unwrap();
    let root_params = ca_params("CLI Test Root CA");
    let root_raw = root_params.self_signed(&root_key).unwrap();
    let root_issuer = Issuer::new(root_params, root_key);

    let intermediate_key = KeyPair::generate().unwrap();
    let intermediate_params = ca_params("CLI Test Intermediate CA");
    let intermediate_raw = intermediate_params
        .signed_by(&intermediate_key, &root_issuer)
        .unwrap();
    let intermediate_issuer = Issuer::new(intermediate_params, intermediate_key);

    let mut leaf_params = CertificateParams::new(vec!["cli.example".to_string()]).unwrap();
    leaf_params.not_before = not_before;
    leaf_params.not_after = not_after;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_raw = leaf_params
        .signed_by(&leaf_key, &intermediate_issuer)
        .unwrap();

    let leaf_path = directory.path().join("leaf.pem");
    let intermediate_path = directory.path().join("intermediate.pem");
    let root_path = directory.path().join("root.pem");
    fs::write(&leaf_path, leaf_raw.pem()).unwrap();
    fs::write(&intermediate_path, intermediate_raw.pem()).unwrap();
    fs::write(&root_path, root_raw.pem()).unwrap();

    (
        leaf_path.display().to_string(),
        intermediate_path.display().to_string(),
        root_path.display().to_string(),
    )
}

#[test]
fn inspect_prints_certificate_fields() {
    let directory = TempDir::new().unwrap();
    let (leaf_path, _, _) = write_chain(&directory);

    Command::cargo_bin("cert-cli")
        .unwrap()
        .args(["inspect", &leaf_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("Subject:"))
        .stdout(predicate::str::contains("cli.example"))
        .stdout(predicate::str::contains("SHA-256:"));
}

#[test]
fn verify_reports_untrusted_without_chain() {
    let directory = TempDir::new().unwrap();
    let (leaf_path, _, _) = write_chain(&directory);

    Command::cargo_bin("cert-cli")
        .unwrap()
        .args(["verify", &leaf_path])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Untrusted root"));
}

#[test]
fn verify_reports_valid_json_with_chain() {
    let directory = TempDir::new().unwrap();
    let (leaf_path, intermediate_path, root_path) = write_chain(&directory);

    Command::cargo_bin("cert-cli")
        .unwrap()
        .args([
            "verify",
            &leaf_path,
            "--chain",
            &intermediate_path,
            "--trust",
            &root_path,
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"Valid\""));
}
