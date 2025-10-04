use clap::builder::TypedValueParser;
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector};
use std::sync::Arc;
use rustls::client::danger::{ServerCertVerifier, HandshakeSignatureValid};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Sha256, Digest};

pub(crate) mod connection;

#[derive(Debug)]
pub(crate) struct FingerprintVerifier {
    expected_fingerprint: String,  
}

impl FingerprintVerifier {
    pub fn new(fingerprint: String) -> Self {
        Self {
            expected_fingerprint: fingerprint.to_lowercase(),
        }
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let hash_result = hasher.finalize();
        let actual_fingerprint = hash_result.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        
        if actual_fingerprint == self.expected_fingerprint {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(CertificateError::Other(
                rustls::OtherError(Arc::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Certificate fingerprint mismatch: expected {}, got {}",
                        self.expected_fingerprint, actual_fingerprint
                    ),
                )))
            )))
        }
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
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DeployPathPair(String, String);

#[derive(Clone)]
pub(crate) struct DeployPathPairValueParser;

impl TypedValueParser for DeployPathPairValueParser {
    type Value = DeployPathPair;

    fn parse_ref(
        &self,
        _cmd: &clap::Command,
        _arg: Option<&clap::Arg>,
        value: &std::ffi::OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let s = value.to_str().ok_or_else(|| {
            clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                "Value must be valid UTF-8",
            )
        })?;
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(clap::Error::raw(
                clap::error::ErrorKind::InvalidValue,
                "Value must be in the format <local_path>:<remote_path>",
            ));
        }
        Ok(DeployPathPair(parts[0].to_string(), parts[1].to_string()))
    }
}

pub(crate) async fn run(
    server: &String,
    fingerprint: &String,
    password: &String,
    paths: Vec<&DeployPathPair>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!(
        "Deploying to server {}, fingerprint: {}, paths: {:?}",
        server, fingerprint, paths
    );
    for path in &paths {
        println!(
            "Uploading local path: {} to remote path: {}",
            path.0, path.1
        );
    }
    let verifier = FingerprintVerifier::new(fingerprint.clone());
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    
    let connector = TlsConnector::from(Arc::new(config));
    
    let stream = TcpStream::connect(server).await?;

    let domain = rustls_pki_types::ServerName::try_from("localhost".to_owned())
        .expect("localhost should be a valid server name");
    let tls_stream = connector.connect(domain, stream).await?;
    

    let conn = Arc::new(connection::Connection::new(
        password.clone(),
        paths
            .iter()
            .map(|p| DeployPathPair(p.0.clone(), p.1.clone()))
            .collect(),
    ));
    conn.run(tls_stream).await?;
    Ok(())
}
