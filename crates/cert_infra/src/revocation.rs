use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use cert_core::{Certificate, RevocationStatus, build_ocsp_request, check_crl, check_ocsp};
use chrono::Utc;

use crate::config::{RevocationConfig, RevocationMode};

pub use cert_core::RevocationCheck;

#[derive(Debug, Clone)]
struct CacheEntry {
    fetched_at: Instant,
    body: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct RevocationCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
}

impl RevocationCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, url: &str, max_age: Duration) -> Option<Vec<u8>> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(url)?;
        if entry.fetched_at.elapsed() <= max_age {
            Some(entry.body.clone())
        } else {
            None
        }
    }

    fn insert(&self, url: String, body: Vec<u8>) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(
                url,
                CacheEntry {
                    fetched_at: Instant::now(),
                    body,
                },
            );
        }
    }
}

pub fn check_revocation(
    target: &Certificate,
    issuer: Option<&Certificate>,
    config: &RevocationConfig,
    cache: &RevocationCache,
) -> RevocationCheck {
    let now = Utc::now();
    if config.mode == RevocationMode::Off {
        return unknown(now, "revocation checking is disabled");
    }

    let Some(issuer) = issuer else {
        return unknown(now, "issuer certificate is not available");
    };

    let mut errors = Vec::new();
    let mut fallback = None;

    if config.mode.uses_ocsp() {
        match check_ocsp_endpoints(target, issuer, config, cache, now) {
            Ok(check) => match check.status {
                RevocationStatus::Revoked { .. } | RevocationStatus::Good => return check,
                RevocationStatus::Unknown { .. } => fallback = Some(check),
            },
            Err(error) => errors.push(error),
        }
    }

    if config.mode.uses_crl() {
        match check_crl_endpoints(target, issuer, config, cache, now) {
            Ok(check) => match check.status {
                RevocationStatus::Revoked { .. } | RevocationStatus::Good => return check,
                RevocationStatus::Unknown { .. } => fallback = Some(check),
            },
            Err(error) => errors.push(error),
        }
    }

    if let Some(check) = fallback {
        return check;
    }

    unknown(
        now,
        if errors.is_empty() {
            "no usable revocation endpoint was found".to_string()
        } else {
            errors.join("; ")
        },
    )
}

fn check_ocsp_endpoints(
    target: &Certificate,
    issuer: &Certificate,
    config: &RevocationConfig,
    cache: &RevocationCache,
    now: chrono::DateTime<Utc>,
) -> Result<RevocationCheck, String> {
    if target.ocsp_responders.is_empty() {
        return Err("certificate has no OCSP responder".to_string());
    }

    let request = build_ocsp_request(target, issuer).map_err(|error| error.to_string())?;
    let agent = http_agent(config);
    let mut errors = Vec::new();

    for url in &target.ocsp_responders {
        if !is_http_url(url) {
            errors.push(format!("unsupported OCSP URL {url}"));
            continue;
        }

        let response = agent
            .post(url)
            .header("Content-Type", "application/ocsp-request")
            .header("Accept", "application/ocsp-response")
            .send(request.as_slice());

        let body = match response {
            Ok(mut response) => match response.body_mut().read_to_vec() {
                Ok(body) => body,
                Err(error) => {
                    errors.push(format!("{url}: {error}"));
                    continue;
                }
            },
            Err(error) => {
                errors.push(format!("{url}: {error}"));
                continue;
            }
        };

        cache.insert(url.clone(), body.clone());
        match check_ocsp(target, issuer, &body, now, url) {
            Ok(check) => return Ok(check),
            Err(error) => errors.push(format!("{url}: {error}")),
        }
    }

    Err(errors.join("; "))
}

fn check_crl_endpoints(
    target: &Certificate,
    issuer: &Certificate,
    config: &RevocationConfig,
    cache: &RevocationCache,
    now: chrono::DateTime<Utc>,
) -> Result<RevocationCheck, String> {
    if target.crl_distribution_points.is_empty() {
        return Err("certificate has no CRL distribution point".to_string());
    }

    let agent = http_agent(config);
    let max_age = Duration::from_secs(config.cache_secs);
    let mut errors = Vec::new();

    for url in &target.crl_distribution_points {
        if !is_http_url(url) {
            errors.push(format!("unsupported CRL URL {url}"));
            continue;
        }

        let body = match cache.get(url, max_age) {
            Some(body) => body,
            None => {
                let mut response = match agent.get(url).call() {
                    Ok(response) => response,
                    Err(error) => {
                        errors.push(format!("{url}: {error}"));
                        continue;
                    }
                };
                let body = match response.body_mut().read_to_vec() {
                    Ok(body) => body,
                    Err(error) => {
                        errors.push(format!("{url}: {error}"));
                        continue;
                    }
                };
                cache.insert(url.clone(), body.clone());
                body
            }
        };

        let der = crl_der(&body);
        match check_crl(target, issuer, &der, now, url) {
            Ok(check) => return Ok(check),
            Err(error) => errors.push(format!("{url}: {error}")),
        }
    }

    Err(errors.join("; "))
}

fn http_agent(config: &RevocationConfig) -> ureq::Agent {
    let timeout = Duration::from_secs(config.timeout_secs.max(1));
    let agent_config = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .build();
    ureq::Agent::new_with_config(agent_config)
}

fn is_http_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

fn crl_der(body: &[u8]) -> Vec<u8> {
    if body.starts_with(b"-----BEGIN") {
        if let Ok((_, pem)) = x509_parser::pem::parse_x509_pem(body) {
            return pem.contents;
        }
    }
    body.to_vec()
}

fn unknown(now: chrono::DateTime<Utc>, message: impl Into<String>) -> RevocationCheck {
    RevocationCheck {
        status: RevocationStatus::Unknown {
            message: message.into(),
        },
        source: "revocation".to_string(),
        checked_at: now,
        details: Vec::new(),
    }
}
