use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use cert_core::CertSource;
use cert_infra::fetch_chain;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

#[test]
fn fetches_chain_from_tls_server() {
    let key = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = key.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let connection = ServerConnection::new(Arc::new(config)).unwrap();
        let mut stream = StreamOwned::new(connection, tcp);
        while stream.conn.is_handshaking() {
            if stream.conn.complete_io(&mut stream.sock).is_err() {
                break;
            }
        }
    });

    let chain = fetch_chain("127.0.0.1", port).unwrap();
    server.join().unwrap();

    assert_eq!(chain.certificates.len(), 1);
    assert!(
        chain.certificates[0]
            .san
            .iter()
            .any(|name| name == "localhost")
    );
    assert!(matches!(
        chain.certificates[0].source,
        CertSource::Network { .. }
    ));
}
