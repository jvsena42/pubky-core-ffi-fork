//! `SSL_CERT_FILE` and `SSL_CERT_DIR`, trusted on top of the bundled Mozilla roots.
//!
//! Behind a TLS-intercepting proxy the proxy's CA is named by these variables, and without it every
//! homeserver, relay and ICANN request fails with `UnknownIssuer` (pubky/pubky-homeserver#648). Read
//! the way loopky's `CertificateEnvironment` reads them on the JVM side, so both halves of the CLI
//! trust the same set.
//!
//! Parsed one certificate at a time because `add_root_certificates_pem` rejects a whole bundle on
//! one unusable certificate, and a system bundle carrying one odd entry must not take the proxy's
//! CA down with it. An unreadable file or directory is skipped silently: the JVM side already
//! reports it, and a second warning for the same path is noise on every command's stderr.

use base64::engine::general_purpose::STANDARD as base64_engine;
use base64::Engine;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use std::path::Path;

/// Every usable certificate the environment names, deduplicated, in file order.
pub(crate) fn env_certificates(var: impl Fn(&str) -> Option<String>) -> Vec<CertificateDer<'static>> {
    let mut certificates: Vec<CertificateDer<'static>> = Vec::new();
    let mut add = |found: Vec<CertificateDer<'static>>| {
        for certificate in found {
            if !certificates.contains(&certificate) {
                certificates.push(certificate);
            }
        }
    };

    if let Some(path) = var("SSL_CERT_FILE").filter(|value| !value.trim().is_empty()) {
        add(read_pem(Path::new(&path)));
    }
    if let Some(dirs) = var("SSL_CERT_DIR") {
        let separator = if cfg!(windows) { ';' } else { ':' };
        for dir in dirs.split(separator).filter(|dir| !dir.trim().is_empty()) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            let mut files: Vec<_> = entries
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| path.is_file())
                .collect();
            files.sort();
            for file in files {
                add(read_pem(&file));
            }
        }
    }
    certificates
}

/// The certificates in [env_certificates] that rustls accepts as trust anchors. The rest are
/// dropped with a warning.
pub(crate) fn usable(certificates: Vec<CertificateDer<'static>>) -> Vec<CertificateDer<'static>> {
    certificates
        .into_iter()
        .filter(|certificate| {
            let mut store = rustls::RootCertStore::empty();
            match store.add(certificate.clone()) {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!(
                        target: "pubkycore",
                        "ignoring a certificate from SSL_CERT_FILE/SSL_CERT_DIR: {error}"
                    );
                    false
                }
            }
        })
        .collect()
}

pub(crate) fn to_pem(certificate: &CertificateDer<'_>) -> String {
    let encoded = base64_engine.encode(certificate.as_ref());
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// Every `CERTIFICATE` block in [path]. Other PEM sections (keys, CRLs) are skipped; a malformed
/// block ends the file there rather than discarding what came before it.
fn read_pem(path: &Path) -> Vec<CertificateDer<'static>> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    CertificateDer::pem_slice_iter(&bytes)
        .map_while(Result::ok)
        .collect()
}
