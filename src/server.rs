use self::session::Session;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::vec::Vec;
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, rustls};
mod session;

mod config;

fn print_cert_fingerprint(cert: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 加载证书并计算DER编码内容的指纹（与客户端验证逻辑一致）
    let certs: Vec<CertificateDer> =
        CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?;
    if let Some(cert_der) = certs.first() {
        let mut hasher = Sha256::new();
        hasher.update(cert_der.as_ref()); // 计算DER编码内容的SHA256
        let result = hasher.finalize();
        let fingerprint = result
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        println!("Certificate SHA256 fingerprint: {}", fingerprint);
    } else {
        return Err("No certificates found in the provided file".into());
    }
    Ok(())
}

pub(crate) async fn run(
    listen: &String,
    cert: &String,
    private_key: &String,
    password: &String,
    paths: Vec<&PathBuf>,
    script: Option<&String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!(
        "Starting server on {}, cert: {}, key: {}, dirs: {:?}, script: {:?}",
        listen, cert, private_key, paths, script
    );
    self::config::set_config(
        password.clone(),
        paths.iter().map(|p| p.to_path_buf()).collect(),
        script.map(|s| s.to_string()),
    );
    let certs = CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?;
    let private_key = PrivateKeyDer::from_pem_file(private_key)?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(listen).await?;
    println!("Server is running and listening on {}", listen);
    print_cert_fingerprint(cert)?;
    loop {
        let (stream, _) = listener.accept().await?;
        let session = Arc::new(Session::new());
        tokio::spawn(session.run(stream, acceptor.clone()));
    }
}
