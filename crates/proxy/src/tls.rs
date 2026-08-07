//! TLS on both legs.
//!
//! Postgres does not use ALPN or a separate port: the client sends an
//! `SSLRequest` packet, the server answers with a single byte `S` or `N`, and
//! only then does the TLS handshake begin. Both legs here follow that dance.
//!
//! A masking proxy reachable over plaintext is not a security boundary — anyone
//! on the path reads the values the proxy exists to protect.

use std::io;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// How to reach the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum BackendTls {
    /// Plaintext to the backend. Fine when it is a unix socket away.
    #[default]
    Disable,
    /// Encrypt, but do not authenticate the server's certificate.
    ///
    /// Matches libpq's `sslmode=require`, and carries libpq's caveat: it stops
    /// passive eavesdropping, not an active man in the middle. Certificate
    /// verification against a CA is the follow-up (see `docs/phase4.md`).
    Require,
}

/// Anything we can run the protocol over: plain TCP or a TLS session.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

pub type BoxStream = Box<dyn Stream>;

pub fn load_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let certs: Vec<CertificateDer<'static>> = {
        let bytes = std::fs::read(cert_path).with_context(|| format!("reading {cert_path}"))?;
        rustls_pemfile::certs(&mut bytes.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("parsing certificates from {cert_path}"))?
    };
    if certs.is_empty() {
        bail!("{cert_path} contained no certificates");
    }

    let key = {
        let bytes = std::fs::read(key_path).with_context(|| format!("reading {key_path}"))?;
        rustls_pemfile::private_key(&mut bytes.as_slice())
            .with_context(|| format!("parsing a private key from {key_path}"))?
            .with_context(|| format!("{key_path} contained no private key"))?
    };

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building the TLS server config")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Shared by the proxy's backend leg and by catalog resolution, so both trust
/// the same thing and neither can be TLS-capable while the other is not.
pub fn backend_client_config() -> ClientConfig {
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth()
}

pub fn backend_connector() -> TlsConnector {
    TlsConnector::from(Arc::new(backend_client_config()))
}

/// Encryption without authentication, matching `sslmode=require`.
///
/// Named for what it does rather than something reassuring, because it is a real
/// limitation: it defeats a passive listener and not an active attacker who can
/// intercept the connection.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

/// Ask the backend to upgrade, then handshake.
///
/// The `SSLRequest` packet is `[len=8][code=80877103]`, answered by exactly one
/// byte before any TLS bytes flow.
///
/// `hostname` becomes the TLS SNI. That is not cosmetic: managed Postgres that
/// multiplexes many databases behind one address — Neon among them — routes the
/// connection by SNI, so a placeholder name means the handshake never reaches
/// the right endpoint.
pub async fn upgrade_backend(
    mut stream: tokio::net::TcpStream,
    hostname: &str,
) -> Result<BoxStream> {
    let mut request = [0u8; 8];
    request[..4].copy_from_slice(&8i32.to_be_bytes());
    request[4..].copy_from_slice(&crate::protocol::SSL_REQUEST_CODE.to_be_bytes());
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut answer = [0u8; 1];
    stream.read_exact(&mut answer).await?;
    match answer[0] {
        b'S' => {}
        b'N' => bail!(
            "backend_tls = \"require\" but the server refused TLS \
             (is `ssl = on` in postgresql.conf?)"
        ),
        other => bail!("unexpected reply {:?} to SSLRequest", other as char),
    }

    let server_name = ServerName::try_from(hostname.to_string())
        .with_context(|| format!("{hostname} is not a valid TLS server name"))?;
    let tls = backend_connector()
        .connect(server_name, stream)
        .await
        .map_err(|err: io::Error| anyhow::anyhow!("backend TLS handshake failed: {err}"))?;
    Ok(Box::new(tls))
}
