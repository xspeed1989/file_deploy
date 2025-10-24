use clap::{Command, arg, value_parser};
use tracing::warn;

mod client;
mod data_define;
mod server;

mod file_deploy {
    include!(concat!(env!("OUT_DIR"), "/file_deploy.rs"));
}

fn cli() -> Command {
    Command::new("file-deploy")
        .version("0.1.0")
        .about("A CLI tool for deploying files")
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("serv")
                .about("the server mode, accept file upload")
                .arg(arg!(listen: -l --listen [LISTEN] "listening address").default_value("0.0.0.0:4399"))
                .arg(arg!(cert: -c --cert <CERT> "TLS certificate file path"))
                .arg(arg!(key: -k --key <PRIVATE_KEY> "TLS private key file path"))
                .arg(arg!(password: -p --password <PASSWORD> "set a password for upload authentication"))
                .arg(arg!(script: -s --script [SCRIPT] "a script to run after all files are uploaded"))
                .arg(
                    arg!(<DIR> ... "whitelisted directories to save uploaded files")
                        .value_parser(value_parser!(std::path::PathBuf)),
                ),
        )
        .subcommand(
            Command::new("deploy")
                .about("the deploy mode, upload files to server")
                .arg(arg!(server: -s --server <SERVER> "server address, e.g. 192.168.1.2:4399"))
                .arg(arg!(fingerprint: --fingerprint <FINGERPRINT> "server TLS certificate fingerprint"))
                .arg(arg!(password: -p --password <PASSWORD> "set a password for upload authentication"))
                .arg(arg!(delimiter: -d --delimiter <DELIMITER> "delimiter for path pairs, used to separate local and remote paths").default_value("=>"))
                .arg(arg!(<PATH> ... "path pairs in format: <local_path><delimiter><remote_path>, e.g., ./file.txt=>/data/file.txt")),
        )
}

pub async fn entry() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let mut cmd = cli();
    let matches = cmd.clone().get_matches();
    match matches.subcommand() {
        Some(("serv", sub_m)) => {
            let listen = sub_m.get_one::<String>("listen").unwrap();
            let cert = sub_m.get_one::<String>("cert").unwrap();
            let private_key = sub_m.get_one::<String>("key").unwrap();
            let password = sub_m.get_one::<String>("password").unwrap();
            let dirs: Vec<std::path::PathBuf> = sub_m
                .get_many::<std::path::PathBuf>("DIR")
                .unwrap()
                .map(|p| {
                    // Normalize path separators to '/' for cross-platform compatibility
                    let p = p.to_string_lossy().replace("\\", "/");
                    let p = std::path::PathBuf::from(p);
                    match std::fs::canonicalize(&p) {
                        Ok(canonical_path) => {
                            // Remove Windows UNC prefix \\?\ if present
                            let path_str = canonical_path.to_string_lossy();
                            if path_str.starts_with(r"\\?\") {
                                std::path::PathBuf::from(&path_str[4..])
                            } else {
                                canonical_path
                            }
                        }
                        Err(_) => p.clone(),
                    }
                })
                .collect();
            let dir_refs: Vec<&std::path::PathBuf> = dirs.iter().collect();
            let script = sub_m.get_one::<String>("script");
            return server::run(listen, cert, private_key, password, dir_refs, script).await;
        }
        Some(("deploy", sub_m)) => {
            let server = sub_m.get_one::<String>("server").unwrap();
            let fingerprint = sub_m.get_one::<String>("fingerprint").unwrap();
            let password = sub_m.get_one::<String>("password").unwrap();
            let delimiter = sub_m.get_one::<String>("delimiter").unwrap();
            
            // use delimiter parse PATH parameter
            let path_strings: Vec<&String> = sub_m
                .get_many::<String>("PATH")
                .unwrap()
                .collect();
            
            let paths: Result<Vec<client::DeployPathPair>, String> = path_strings
                .iter()
                .map(|s| {
                    let parts: Vec<&str> = s.splitn(2, delimiter.as_str()).collect();
                    if parts.len() != 2 {
                        Err(format!("Invalid path format: '{}'. Expected format: <local_path>{}<remote_path>", s, delimiter))
                    } else {
                        Ok(client::DeployPathPair::new(parts[0].to_string(), parts[1].to_string()))
                    }
                })
                .collect();
            
            let paths = paths.map_err(|e| Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)) as Box<dyn std::error::Error + Send + Sync>)?;
            let path_refs: Vec<&client::DeployPathPair> = paths.iter().collect();
            
            return client::run(server, fingerprint, password, path_refs).await;
        }
        _ => {
            warn!("No valid subcommand was used");
            cmd.print_help()?;
        }
    }
    Ok(())
}
