use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(&["proto/file_deploy.proto"], &["proto"])?;
    Ok(())
}
