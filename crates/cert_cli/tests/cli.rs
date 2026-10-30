use std::fs;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use assert_cmd::Command;
use predicates::prelude::*;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use tempfile::TempDir;
use time::{Duration, OffsetDateTime};

struct TestChain {
    leaf_path: String,
    intermediate_path: String,
    root_path: String,
    leaf_der: Vec<u8>,
    intermediate_der: Vec<u8>,
    leaf_key_der: Vec<u8>,
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

fn write_chain(directory: &TempDir) -> TestChain {
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

    TestChain {
        leaf_path: leaf_path.display().to_string(),
        intermediate_path: intermediate_path.display().to_string(),
        root_path: root_path.display().to_string(),
        leaf_der: leaf_raw.der().to_vec(),
        intermediate_der: intermediate_raw.der().to_vec(),
        leaf_key_der: leaf_key.serialize_der(),
    }
}

#[test]
fn inspect_prints_certificate_fields() {
    let directory = TempDir::new().unwrap();
    let chain = write_chain(&directory);

    Command::cargo_bin("cert-cli")
        .unwrap()
        .args(["inspect", &chain.leaf_path])
        .assert()
        .success()
        .stdout(predicate::str::contains("Subject:"))
        .stdout(predicate::str::contains("cli.example"))
        .stdout(predicate::str::contains("SHA-256:"));
}

#[test]
fn verify_reports_untrusted_without_chain() {
    let directory = TempDir::new().unwrap();
    let chain = write_chain(&directory);

    Command::cargo_bin("cert-cli")
        .unwrap()
        .args(["verify", &chain.leaf_path])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Untrusted root"));
}

#[test]
fn verify_reports_valid_json_with_chain() {
    let directory = TempDir::new().unwrap();
    let chain = write_chain(&directory);

    Command::cargo_bin("cert-cli")
        .unwrap()
        .args([
            "verify",
            &chain.leaf_path,
            "--chain",
            &chain.intermediate_path,
            "--trust",
            &chain.root_path,
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"Valid\""));
}

#[test]
fn fetch_rejects_invalid_host() {
    Command::cargo_bin("cert-cli")
        .unwrap()
        .args(["fetch", ""])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid server name"));
}

fn serve_once(chain: &TestChain) -> (u16, thread::JoinHandle<()>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(chain.leaf_der.clone()),
                CertificateDer::from(chain.intermediate_der.clone()),
            ],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(chain.leaf_key_der.clone())),
        )
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let connection = ServerConnection::new(Arc::new(config)).unwrap();
        let mut stream = StreamOwned::new(connection, tcp);
        while stream.conn.is_handshaking() {
            if stream.conn.complete_io(&mut stream.sock).is_err() {
                break;
            }
        }
    });
    (port, handle)
}

#[test]
fn verify_accepts_network_target() {
    let directory = TempDir::new().unwrap();
    let chain = write_chain(&directory);
    let (port, server) = serve_once(&chain);

    Command::cargo_bin("cert-cli")
        .unwrap()
        .args([
            "verify",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--trust",
            &chain.root_path,
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"status\": \"Valid\""));

    server.join().unwrap();
}
