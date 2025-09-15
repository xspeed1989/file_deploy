use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::vec::Vec;
use std::fs;

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
    paths: Vec<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // print cert sha256 fingerprint
    println!(
        "Starting server on {}, cert: {}, key: {}, dirs: {:?}",
        listen, cert, private_key, paths
    );
    print_cert_fingerprint(cert)?;
    // Here you would add the logic to start the server
    Ok(())
}
