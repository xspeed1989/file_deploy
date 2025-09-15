use clap::{Command, arg, value_parser};

mod server;
mod client;

fn cli() -> Command {
    Command::new("file-deploy")
        .version("0.1.0")
        .about("A CLI tool for deploying files")
        .allow_external_subcommands(true)
        .subcommand(
            Command::new("serv")
                .about("the server mode, accept file upload")
                .arg(arg!(listen: -l --listen [LISTEN] "listening address").default_value(":4399"))
                .arg(arg!(cert: --cert <CERT> "TLS certificate file path"))
                .arg(arg!(private_key: --private_key <PRIVATE_KEY> "TLS private key file path"))
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
                .arg(arg!(<PATH> ... "files or directories to upload").value_parser(client::DeployPathPairValueParser)),
        )
}

pub async fn entry() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut cmd = cli();
    let matches = cmd.clone().get_matches();
    match matches.subcommand() {
        Some(("serv", sub_m)) => {
            let listen = sub_m.get_one::<String>("listen").unwrap();
            let cert = sub_m.get_one::<String>("cert").unwrap();
            let private_key = sub_m.get_one::<String>("private_key").unwrap();
            let dirs: Vec<&std::path::PathBuf> = sub_m.get_many::<std::path::PathBuf>("DIR").unwrap().collect();
            return server::run(listen, cert, private_key, dirs).await;
            // Here you would add the logic to start the server
        }
        Some(("deploy", sub_m)) => {
            let server = sub_m.get_one::<String>("server").unwrap();
            let fingerprint = sub_m.get_one::<String>("fingerprint").unwrap();
            let paths = sub_m.get_many::<client::DeployPathPair>("PATH").unwrap().collect();
            println!("Deploying to server {}, fingerprint: {}, paths: {:?}", server, fingerprint, paths);
            // Here you would add the logic to deploy files
            return client::run(server, fingerprint, paths).await;
        }
        _ => {
            println!("No valid subcommand was used");
            cmd.print_help()?;
        }
    }
    Ok(())
}
