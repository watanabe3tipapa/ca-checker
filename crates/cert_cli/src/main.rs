use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cert_core::{Certificate, ChainValidationResult, ValidationOptions, validate};
use cert_infra::{load_directory, load_file, load_os_store, trust_anchors_der};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cert-cli", about = "X.509 CA certificate checker")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    ListOs {
        #[arg(long)]
        json: bool,
    },
    Inspect {
        path: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Verify {
        path: PathBuf,
        #[arg(long = "chain")]
        chain: Vec<PathBuf>,
        #[arg(long = "trust")]
        trust: Vec<PathBuf>,
        #[arg(long, default_value_t = 30)]
        warn_days: i64,
        #[arg(long)]
        json: bool,
    },
    Scan {
        dir: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    match cli.command {
        Command::ListOs { json } => list_os(json),
        Command::Inspect { path, json } => inspect(&path, json),
        Command::Verify {
            path,
            chain,
            trust,
            warn_days,
            json,
        } => verify(&path, &chain, &trust, warn_days, json),
        Command::Scan { dir, json } => scan(&dir, json),
    }
}

fn list_os(json: bool) -> anyhow::Result<u8> {
    let store = load_os_store()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&store.certificates)?);
    } else {
        println!(
            "Loaded {} certificate(s) from the OS trust store",
            store.certificates.len()
        );
        for certificate in &store.certificates {
            println!(
                "  [{}] {}",
                certificate.fingerprint_sha256, certificate.subject
            );
        }
        for error in &store.errors {
            eprintln!("warning: {error}");
        }
    }
    Ok(0)
}

fn inspect(path: &Path, json: bool) -> anyhow::Result<u8> {
    let certificates = load_file(path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&certificates)?);
    } else {
        for certificate in &certificates {
            print_certificate(certificate);
        }
    }
    Ok(0)
}

fn verify(
    path: &Path,
    chain_paths: &[PathBuf],
    trust_paths: &[PathBuf],
    warn_days: i64,
    json: bool,
) -> anyhow::Result<u8> {
    let mut certificates = load_file(path)?;
    let target = certificates.remove(0);
    let mut intermediates = certificates;

    for chain_path in chain_paths {
        intermediates.extend(load_file(chain_path)?);
    }

    let anchors = if trust_paths.is_empty() {
        let store = load_os_store()?;
        trust_anchors_der(&store.certificates)
    } else {
        let mut anchors = Vec::new();
        for trust_path in trust_paths {
            anchors.extend(trust_anchors_der(&load_file(trust_path)?));
        }
        anchors
    };
    let options = ValidationOptions {
        now: chrono::Utc::now(),
        warn_days,
    };
    let result = validate(&target, &intermediates, &anchors, &options);

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_validation(&result);
    }

    Ok(if result.status.is_healthy() { 0 } else { 1 })
}

fn scan(dir: &Path, json: bool) -> anyhow::Result<u8> {
    let result = load_directory(dir)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&result.certificates)?);
    } else {
        println!(
            "Found {} certificate(s) in {}",
            result.certificates.len(),
            dir.display()
        );
        for certificate in &result.certificates {
            println!(
                "  [{}] {} <- {}",
                certificate.source.label(),
                certificate.subject,
                certificate.issuer
            );
        }
        for error in &result.errors {
            eprintln!("warning: {error}");
        }
    }
    Ok(0)
}

fn print_certificate(certificate: &Certificate) {
    println!("Subject:            {}", certificate.subject);
    println!("Issuer:             {}", certificate.issuer);
    println!("Serial:             {}", certificate.serial);
    println!(
        "Not before:         {}",
        certificate.not_before.to_rfc3339()
    );
    println!("Not after:          {}", certificate.not_after.to_rfc3339());
    println!("Signature:          {}", certificate.signature_algorithm);
    println!("Key:                {}", certificate.key_algorithm);
    println!("CA:                 {}", certificate.is_ca);
    println!(
        "Path length:        {}",
        certificate
            .path_length
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!("SAN:                {}", format_san(&certificate.san));
    println!("SHA-256:            {}", certificate.fingerprint_sha256);
    println!("Source:             {}", certificate.source.label());
    println!();
}

fn print_validation(result: &ChainValidationResult) {
    println!("Status:   {}", result.status.label());
    println!("Subject:  {}", result.target.subject);
    println!("Issuer:   {}", result.target.issuer);
    println!("Checked:  {}", result.checked_at.to_rfc3339());
    if let Some(anchor) = &result.trust_anchor {
        println!("Anchor:   {}", anchor.subject);
    }
    println!("Errors:   {}", result.errors.len());
    for error in &result.errors {
        println!("  - {error}");
    }
    println!("Warnings: {}", result.warnings.len());
    for warning in &result.warnings {
        println!("  - {warning}");
    }
}

fn format_san(san: &[String]) -> String {
    if san.is_empty() {
        "-".to_string()
    } else {
        san.join(", ")
    }
}
