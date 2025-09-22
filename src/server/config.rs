use std::sync::Mutex;
use std::path::PathBuf;
use lazy_static::lazy_static;

#[derive(Clone)]
pub struct ServerConfig {
    pub password: String,
    pub whitelisted_dirs: Vec<PathBuf>,
}

lazy_static! {
    pub static ref CONFIG: Mutex<ServerConfig> = Mutex::new(ServerConfig {
        password: String::new(),
        whitelisted_dirs: Vec::new(),
    });
}

pub(crate) fn set_config(password: String, whitelisted_dirs: Vec<PathBuf>) {
    let mut config = CONFIG.lock().unwrap();
    config.password = password;
    config.whitelisted_dirs = whitelisted_dirs;
}

pub(crate) fn get_config() -> ServerConfig {
    let config = CONFIG.lock().unwrap();
    return config.clone();
}
