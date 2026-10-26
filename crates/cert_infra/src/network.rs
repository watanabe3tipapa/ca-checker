use cert_core::Certificate;

use crate::InfraError;

pub struct FetchedChain {
    pub host: String,
    pub port: u16,
    pub certificates: Vec<Certificate>,
}

pub fn fetch_chain(_host: &str, _port: u16) -> Result<FetchedChain, InfraError> {
    Err(InfraError::NetworkUnsupported)
}
