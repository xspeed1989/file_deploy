use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::vec::Vec;
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, rustls};
use self::session::Session;
mod session;

mod config;

fn print_cert_fingerprint(cert: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cert_data = fs::read(cert)?;
    let mut hasher = Sha256::new();
    hasher.update(cert_data);
    let result = hasher.finalize();
    println!("Certificate SHA256 fingerprint: {:x}", result);
    Ok(())
}

pub(crate) async fn run(
    listen: &String,
    cert: &String,
    private_key: &String,
    password: &String,
    paths: Vec<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!(
        "Starting server on {}, cert: {}, key: {}, dirs: {:?}",
        listen, cert, private_key, paths
    );
    self::config::set_config(password.clone(), paths.iter().map(|p| p.to_path_buf()).collect());
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
