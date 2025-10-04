use std::sync::Mutex;
use std::path::PathBuf;
use lazy_static::lazy_static;

#[derive(Clone)]
pub struct ServerConfig {
    pub password: String,
    pub whitelisted_dirs: Vec<PathBuf>,
    pub script: Option<String>,
}

lazy_static! {
    pub static ref CONFIG: Mutex<ServerConfig> = Mutex::new(ServerConfig {
        password: String::new(),
        whitelisted_dirs: Vec::new(),
        script: None,
    });
}

pub(crate) fn set_config(password: String, whitelisted_dirs: Vec<PathBuf>, script: Option<String>) {
    let mut config = CONFIG.lock().unwrap();
    config.password = password;
    config.whitelisted_dirs = whitelisted_dirs;
    config.script = script;
}

pub(crate) fn get_config() -> ServerConfig {
    let config = CONFIG.lock().unwrap();
    return config.clone();
}
