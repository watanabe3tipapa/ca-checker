use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use cert_core::{CertSource, Certificate, parse_der_certificate};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned,
    crypto::CryptoProvider,
};

use crate::InfraError;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct FetchedChain {
    pub host: String,
    pub port: u16,
    pub certificates: Vec<Certificate>,
}

/// Connects to `host:port` over TLS and returns the certificate chain that the
/// server presents.
///
/// The peer certificate is deliberately not validated here: this function only
/// collects the chain so that it can be inspected and validated separately
/// against explicit trust anchors. Never treat a fetched certificate as trusted
/// without running `cert_core::validate`.
pub fn fetch_chain(host: &str, port: u16) -> Result<FetchedChain, InfraError> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| InfraError::InvalidServerName(host.to_string()))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|err| network_error(host, port, err))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(UnverifiedPeer { provider }))
        .with_no_client_auth();

    let tcp = connect(host, port)?;
    tcp.set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|err| network_error(host, port, err))?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|err| network_error(host, port, err))?;

    let connection = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|err| network_error(host, port, err))?;
    let mut stream = StreamOwned::new(connection, tcp);

    while stream.conn.is_handshaking() {
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|err| network_error(host, port, err))?;
    }

    let peer = stream
        .conn
        .peer_certificates()
        .filter(|certificates| !certificates.is_empty())
        .ok_or_else(|| InfraError::NoCertificatesFromPeer {
            host: host.to_string(),
            port,
        })?;

    let source = CertSource::Network {
        host: host.to_string(),
        port,
    };
    let mut certificates = Vec::with_capacity(peer.len());
    for der in peer {
        certificates.push(parse_der_certificate(der.as_ref(), source.clone())?);
    }

    Ok(FetchedChain {
        host: host.to_string(),
        port,
        certificates,
    })
}

fn connect(host: &str, port: u16) -> Result<TcpStream, InfraError> {
    use std::net::ToSocketAddrs;

    let addresses: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|err| network_error(host, port, err))?
        .collect();
    if addresses.is_empty() {
        return Err(network_error(
            host,
            port,
            "host did not resolve to any address",
        ));
    }

    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = Some(err),
        }
    }

    match last_error {
        Some(err) => Err(network_error(host, port, err)),
        None => Err(network_error(host, port, "no address could be reached")),
    }
}

fn network_error(host: &str, port: u16, error: impl std::fmt::Display) -> InfraError {
    InfraError::Network {
        host: host.to_string(),
        port,
        message: error.to_string(),
    }
}

/// Accepts any certificate chain so that the presented certificates can be
/// captured even when they are self-signed, expired, or otherwise invalid.
#[derive(Debug)]
struct UnverifiedPeer {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for UnverifiedPeer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_server_name() {
        let error = fetch_chain("", 443).unwrap_err();
        assert!(matches!(error, InfraError::InvalidServerName(_)));
    }
}
