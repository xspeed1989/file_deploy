use clap::builder::TypedValueParser;

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
        let s = value.to_str().ok_or_else(|| clap::Error::raw(
            clap::error::ErrorKind::InvalidValue,
            "Value must be valid UTF-8",
        ))?;
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
    paths: Vec<&DeployPathPair>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Deploying to server {}, fingerprint: {}, paths: {:?}", server, fingerprint, paths);
    for path in paths {
        println!("Uploading local path: {} to remote path: {}", path.0, path.1);
    }
    Ok(())
}