//! TLS trust is either standard WebPKI validation or an explicitly provisioned
//! SHA-256 SubjectPublicKeyInfo pin. Pinning never skips handshake signatures.

use crate::config::{ClientTls, ServerTls};
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Write},
    path::Path,
    sync::Arc,
};
use subtle::ConstantTimeEq;
use x509_parser::{parse_x509_certificate, time::ASN1Time};

/// Load a supplied certificate chain and key, or create a persistent self-signed
/// identity when *both* files are absent. A partial identity is never replaced.
pub fn server_config(config: &ServerTls) -> Result<Arc<rustls::ServerConfig>> {
    ensure!(
        config.cert_path != config.key_path,
        "certificate and key paths must differ"
    );
    match (config.cert_path.try_exists()?, config.key_path.try_exists()?) {
        (false, false) => generate_identity(config)?,
        (true, true) => {}
        _ => bail!("certificate and key must both exist or both be absent; refusing to replace an incomplete TLS identity"),
    }
    let certificates = read_certificates(&config.cert_path)?;
    let mut reader = BufReader::new(File::open(&config.key_path).context("open TLS private key")?);
    let key = rustls_pemfile::private_key(&mut reader)
        .context("parse TLS private key")?
        .context("TLS private key file contains no private key")?;
    // A single configured identity is presented regardless of the client's SNI,
    // including connections which omit SNI entirely. Client verification remains
    // responsible for checking the expected hostname or the provisioned key pin.
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .context("load TLS certificate and matching private key")?;
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    tracing::info!(spki_sha256 = %certificate_pin(&config.cert_path)?, "relay TLS public key fingerprint");
    Ok(Arc::new(tls))
}

/// Build a client verifier. Without a pin, certificate chains, validity and
/// hostname are checked normally against bundled roots and an optional CA file.
pub fn client_config(config: &ClientTls) -> Result<Arc<rustls::ClientConfig>> {
    ensure!(
        config.spki_sha256.is_none() || config.ca_cert_path.is_none(),
        "choose either SPKI pinning or a custom CA"
    );
    let provider = Arc::new(ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    let mut tls = if let Some(pin) = &config.spki_sha256 {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
                expected: parse_pin(pin)?,
                provider,
            }))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = &config.ca_cert_path {
            for certificate in read_certificates(path)? {
                roots.add(certificate).context("invalid CA certificate")?;
            }
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(tls))
}

/// Configure ClientHello SNI independently from the TLS verification identity.
/// The connector must still receive the endpoint's ServerName, even with SNI
/// disabled; turning off SNI never disables hostname, CA or public-key checks.
pub fn client_config_for_relay(
    config: &ClientTls,
    enable_sni: bool,
) -> Result<Arc<rustls::ClientConfig>> {
    let mut tls = client_config(config)?;
    Arc::make_mut(&mut tls).enable_sni = enable_sni;
    Ok(tls)
}

/// Return the leaf certificate's public-key fingerprint in `sha256/BASE64`
/// format. Provision this value through a separate, trusted channel.
pub fn certificate_pin(path: &Path) -> Result<String> {
    let certificates = read_certificates(path)?;
    let digest = spki_digest(certificates[0].as_ref()).context("read leaf public key")?;
    Ok(format!("sha256/{}", STANDARD.encode(digest)))
}

fn parse_pin(pin: &str) -> Result<[u8; 32]> {
    let encoded = pin
        .strip_prefix("sha256/")
        .context("SPKI fingerprint must use sha256/BASE64 format")?;
    let decoded = STANDARD
        .decode(encoded)
        .context("invalid base64 SPKI fingerprint")?;
    let digest: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("SPKI SHA-256 fingerprint must contain exactly 32 bytes"))?;
    ensure!(
        STANDARD.encode(digest) == encoded,
        "SPKI fingerprint must use canonical padded base64"
    );
    Ok(digest)
}

fn spki_digest(der: &[u8]) -> Result<[u8; 32]> {
    let (remaining, certificate) =
        parse_x509_certificate(der).map_err(|_| anyhow::anyhow!("invalid X.509 certificate"))?;
    ensure!(
        remaining.is_empty(),
        "trailing bytes after X.509 certificate"
    );
    Ok(Sha256::digest(certificate.public_key().raw).into())
}

fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("open certificate file {}", path.display()))?,
    );
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<std::io::Result<Vec<_>>>()
        .context("parse PEM certificates")?;
    ensure!(
        !certificates.is_empty(),
        "certificate file contains no PEM certificates"
    );
    Ok(certificates)
}

fn generate_identity(config: &ServerTls) -> Result<()> {
    ensure!(
        !config.names.is_empty(),
        "at least one TLS certificate name is required"
    );
    let key = rcgen::KeyPair::generate().context("generate TLS private key")?;
    let certificate = rcgen::CertificateParams::new(config.names.clone())?
        .self_signed(&key)
        .context("generate self-signed certificate")?;
    for path in [&config.cert_path, &config.key_path] {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).context("create TLS identity directory")?;
        }
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // create_new protects existing files even if another process creates them
    // between the existence check and this write.
    let mut key_file = options
        .open(&config.key_path)
        .context("create TLS private key")?;
    key_file
        .write_all(key.serialize_pem().as_bytes())
        .context("write TLS private key")?;
    key_file.sync_all()?;
    let mut cert_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config.cert_path)
        .context("create TLS certificate")?;
    cert_file
        .write_all(certificate.pem().as_bytes())
        .context("write TLS certificate")?;
    cert_file.sync_all()?;
    Ok(())
}

#[derive(Debug)]
struct PinnedVerifier {
    expected: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        let digest = spki_digest(end_entity.as_ref())
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if !bool::from(digest.ct_eq(&self.expected)) {
            return Err(Error::General(
                "server public-key fingerprint does not match the configured SPKI pin".into(),
            ));
        }
        let (_, certificate) = parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let now = i64::try_from(now.as_secs())
            .ok()
            .and_then(|timestamp| ASN1Time::from_timestamp(timestamp).ok())
            .ok_or(Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if now < certificate.validity().not_before {
            return Err(Error::InvalidCertificate(CertificateError::NotValidYet));
        }
        if now > certificate.validity().not_after {
            return Err(Error::InvalidCertificate(CertificateError::Expired));
        }
        // This authorizes the pinned public key, not the handshake. Rustls next
        // invokes a signature callback to prove the peer owns its private key.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
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

    fn identity(directory: &Path) -> ServerTls {
        ServerTls {
            cert_path: directory.join("cert.pem"),
            key_path: directory.join("key.pem"),
            names: vec!["localhost".into()],
        }
    }

    #[test]
    fn generated_identity_is_reused_and_partial_identity_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let config = identity(dir.path());
        server_config(&config).unwrap();
        let pin = certificate_pin(&config.cert_path).unwrap();
        let key = fs::read(&config.key_path).unwrap();
        server_config(&config).unwrap();
        assert_eq!(pin, certificate_pin(&config.cert_path).unwrap());
        assert_eq!(key, fs::read(&config.key_path).unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&config.key_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_file(&config.cert_path).unwrap();
        assert!(server_config(&config).is_err());
        assert_eq!(key, fs::read(&config.key_path).unwrap());
    }

    #[test]
    fn pin_hashes_public_key_not_certificate() {
        let key = rcgen::KeyPair::generate().unwrap();
        let first = rcgen::CertificateParams::new(vec!["one.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let second = rcgen::CertificateParams::new(vec!["two.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        assert_ne!(first.der(), second.der());
        assert_eq!(
            spki_digest(first.der()).unwrap(),
            spki_digest(second.der()).unwrap()
        );
    }

    #[test]
    fn malformed_pins_are_rejected() {
        for pin in ["", "sha256/xyz", "SHA256/AAAA", "sha256/AA=="] {
            assert!(parse_pin(pin).is_err());
        }
    }

    async fn handshake(
        server: Arc<rustls::ServerConfig>,
        client: Arc<rustls::ClientConfig>,
        name: &'static str,
    ) -> bool {
        handshake_observed_sni(server, client, ServerName::try_from(name).unwrap())
            .await
            .is_ok()
    }

    async fn handshake_observed_sni(
        server: Arc<rustls::ServerConfig>,
        client: Arc<rustls::ClientConfig>,
        name: ServerName<'static>,
    ) -> Result<Option<String>> {
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let acceptor = tokio_rustls::TlsAcceptor::from(server);
        let connector = tokio_rustls::TlsConnector::from(client);
        let (server, client) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                acceptor.accept(server_io),
                connector.connect(name, client_io)
            )
        })
        .await
        .context("test TLS handshake timed out")?;
        client.context("client TLS handshake")?;
        let server = server.context("server TLS handshake")?;
        Ok(server.get_ref().1.server_name().map(str::to_owned))
    }

    #[tokio::test]
    async fn actual_tls_handshake_accepts_pin_and_rejects_wrong_pin() {
        let dir = tempfile::tempdir().unwrap();
        let config = identity(dir.path());
        let server = server_config(&config).unwrap();
        let pin = certificate_pin(&config.cert_path).unwrap();
        let good = client_config(&ClientTls {
            spki_sha256: Some(pin),
            ca_cert_path: None,
        })
        .unwrap();
        // Pinning explicitly authenticates the configured key, even when the URL
        // uses an IP or hostname outside the generated certificate's SANs.
        assert!(handshake(server.clone(), good, "different.example").await);
        for enable_sni in [true, false] {
            let bad = client_config_for_relay(
                &ClientTls {
                    spki_sha256: Some(format!("sha256/{}", STANDARD.encode([0; 32]))),
                    ca_cert_path: None,
                },
                enable_sni,
            )
            .unwrap();
            assert!(!handshake(server.clone(), bad, "localhost").await);
        }
    }

    #[tokio::test]
    async fn relay_accepts_default_custom_absent_and_ip_sni() {
        let dir = tempfile::tempdir().unwrap();
        let config = identity(dir.path());
        let server = server_config(&config).unwrap();
        let trust = ClientTls {
            spki_sha256: Some(certificate_pin(&config.cert_path).unwrap()),
            ca_cert_path: None,
        };
        for (name, enable_sni, expected) in [
            ("localhost", true, Some("localhost")),
            ("custom.example", true, Some("custom.example")),
            ("localhost", false, None),
            ("127.0.0.1", true, None),
            ("::1", true, None),
        ] {
            let client = client_config_for_relay(&trust, enable_sni).unwrap();
            let observed =
                handshake_observed_sni(server.clone(), client, ServerName::try_from(name).unwrap())
                    .await
                    .unwrap();
            assert_eq!(
                observed.as_deref(),
                expected,
                "name={name}, SNI={enable_sni}"
            );
        }
    }

    #[derive(Debug)]
    struct FixedCertificate(Arc<rustls::sign::CertifiedKey>);

    impl rustls::server::ResolvesServerCert for FixedCertificate {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    #[tokio::test]
    async fn pinned_certificate_without_its_private_key_cannot_complete_handshake() {
        let genuine_key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&genuine_key)
            .unwrap();
        let pin = format!(
            "sha256/{}",
            STANDARD.encode(spki_digest(certificate.der()).unwrap())
        );
        let attacker_key = rcgen::KeyPair::generate().unwrap();
        let attacker_der =
            rustls::pki_types::PrivateKeyDer::Pkcs8(attacker_key.serialize_der().into());
        let certified_key = rustls::sign::CertifiedKey::new(
            vec![certificate.der().clone()],
            ring::sign::any_supported_type(&attacker_der).unwrap(),
        );
        // A custom resolver permits a deliberately mismatched key for this
        // negative test. The certificate pin matches, but the signature cannot.
        for protocol in [&rustls::version::TLS13, &rustls::version::TLS12] {
            let server =
                rustls::ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
                    .with_protocol_versions(&[protocol])
                    .unwrap()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(FixedCertificate(Arc::new(
                        certified_key.clone(),
                    ))));
            let client = client_config(&ClientTls {
                spki_sha256: Some(pin.clone()),
                ca_cert_path: None,
            })
            .unwrap();
            assert!(!handshake(Arc::new(server), client, "localhost").await);
        }
    }

    #[tokio::test]
    async fn ca_verification_keeps_hostname_checks() {
        let dir = tempfile::tempdir().unwrap();
        let config = identity(dir.path());
        let server = server_config(&config).unwrap();
        let client = client_config(&ClientTls {
            spki_sha256: None,
            ca_cert_path: Some(config.cert_path),
        })
        .unwrap();
        assert!(handshake(server.clone(), client.clone(), "localhost").await);
        assert!(!handshake(server, client, "other.example").await);
    }

    #[tokio::test]
    async fn disabling_sni_keeps_ca_hostname_verification() {
        let dir = tempfile::tempdir().unwrap();
        let config = identity(dir.path());
        let server = server_config(&config).unwrap();
        let client = client_config_for_relay(
            &ClientTls {
                spki_sha256: None,
                ca_cert_path: Some(config.cert_path),
            },
            false,
        )
        .unwrap();
        assert_eq!(
            handshake_observed_sni(
                server.clone(),
                client.clone(),
                ServerName::try_from("localhost").unwrap(),
            )
            .await
            .unwrap(),
            None,
        );
        assert!(!handshake(server, client, "other.example").await);
    }
}
