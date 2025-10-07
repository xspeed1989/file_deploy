use crate::data_define::*;
use prost::Message;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::TcpStream;
use tokio::sync::{Mutex as AsyncMutex, Notify, oneshot};
use tokio::task::JoinSet;
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::data_define;
use crate::file_deploy;
use crate::server::config::get_config;

pub(crate) struct Session {
    peer: AsyncMutex<String>,
    authenticated: AsyncMutex<bool>,
    write_queue: AsyncMutex<VecDeque<Vec<u8>>>,
    notify: Notify,
    file_handles: AsyncMutex<std::collections::HashMap<String, tokio::fs::File>>,
    need_stop: AtomicBool,
}

fn is_valid_path(path: &str) -> bool {
    if path.contains("..") {
        println!("Path contains '..': {}", path);
        return false;
    }
    let config = get_config();
    for white_dir in config.whitelisted_dirs {
        let white_dir = white_dir.to_str().unwrap().to_string();
        #[cfg(target_os = "windows")]
        let path = path.replace("/", "\\");
        if path.starts_with(white_dir.trim_end_matches(std::path::MAIN_SEPARATOR)) {
            return true;
        }
    }
    println!("Path not allowed: {}", path);
    false
}

impl Session {
    pub(crate) fn new() -> Self {
        Session {
            peer: AsyncMutex::new(String::new()),
            authenticated: AsyncMutex::new(false),
            write_queue: AsyncMutex::new(VecDeque::new()),
            notify: Notify::new(),
            file_handles: AsyncMutex::new(std::collections::HashMap::new()),
            need_stop: AtomicBool::new(false),
        }
    }

    async fn is_authenticated(self: Arc<Self>) -> bool {
        *self.authenticated.lock().await
    }

    async fn on_auth(self: Arc<Self>, payload: &[u8]) {
        let auth_req = file_deploy::AuthRequest::decode(payload);
        if auth_req.is_ok() {
            let auth_req = auth_req.unwrap();
            let config = get_config();
            if auth_req.password == config.password {
                println!(
                    "Authentication successful, peer: {}",
                    self.peer.lock().await
                );
                *self.authenticated.lock().await = true;
            } else {
                println!(
                    "Authentication failed: incorrect password, {}, peer: {}",
                    auth_req.password,
                    self.peer.lock().await
                );
            }
        }
        let auth_resp = file_deploy::AuthResponse {
            success: *self.authenticated.lock().await,
        };
        let packet = package_data(Command::CmdAuthenticate, auth_resp);
        self.post_send(packet).await;
    }

    async fn on_mkdir(self: Arc<Self>, payload: &[u8]) {
        if !self.clone().is_authenticated().await {
            println!(
                "MkDir request but not authenticated, peer: {}",
                self.peer.lock().await
            );
            let resp = file_deploy::MkDirResponse {
                success: false,
                error: "Not authenticated".to_string(),
            };
            let packet = package_data(Command::CmdMkDir, resp);
            self.post_send(packet).await;
            return;
        }
        let mk_dir_req = file_deploy::MkDirRequest::decode(payload);
        if !mk_dir_req.is_ok() {
            println!("Invalid MkDir request, peer: {}", self.peer.lock().await);
            let resp = file_deploy::MkDirResponse {
                success: false,
                error: "Invalid request".to_string(),
            };
            let packet = package_data(Command::CmdMkDir, resp);
            self.post_send(packet).await;
            return;
        }
        let mk_dir_req = mk_dir_req.unwrap();
        println!(
            "MkDir request: {}, peer: {}",
            mk_dir_req.absolute_path,
            self.peer.lock().await
        );
        if !is_valid_path(&mk_dir_req.absolute_path) {
            println!(
                "MkDir request with invalid path: {}, peer: {}",
                mk_dir_req.absolute_path,
                self.peer.lock().await
            );
            let resp = file_deploy::MkDirResponse {
                success: false,
                error: "Path not allowed".to_string(),
            };
            let packet = package_data(Command::CmdMkDir, resp);
            self.post_send(packet).await;
            return;
        }
        let result = tokio::fs::create_dir_all(&mk_dir_req.absolute_path).await;
        let resp = if result.is_ok() {
            file_deploy::MkDirResponse {
                success: true,
                error: "".to_string(),
            }
        } else {
            println!(
                "Failed to create directory, peer: {}",
                self.peer.lock().await
            );
            file_deploy::MkDirResponse {
                success: false,
                error: format!("Failed to create directory: {}", result.err().unwrap()),
            }
        };
        let packet = package_data(Command::CmdMkDir, resp);
        self.post_send(packet).await;
    }

    async fn on_start_upload(self: Arc<Self>, payload: &[u8]) {
        if !self.clone().is_authenticated().await {
            println!(
                "Start upload request but not authenticated, peer: {}",
                self.peer.lock().await
            );
            let resp = file_deploy::StartUploadResponse {
                success: false,
                error: "Not authenticated".to_string(),
            };
            let packet = package_data(Command::CmdStartUpload, resp);
            self.post_send(packet).await;
            return;
        }

        let start_upload_req = file_deploy::StartUploadRequest::decode(payload);
        if !start_upload_req.is_ok() {
            println!(
                "Invalid StartUpload request, peer: {}",
                self.peer.lock().await
            );
            let resp = file_deploy::StartUploadResponse {
                success: false,
                error: "Invalid request".to_string(),
            };
            let packet = package_data(Command::CmdStartUpload, resp);
            self.post_send(packet).await;
            return;
        }
        let start_upload_req = start_upload_req.unwrap();
        println!(
            "Start upload request for file: {}, size: {}, peer: {}",
            start_upload_req.absolute_path,
            start_upload_req.total_size,
            self.peer.lock().await
        );
        if !is_valid_path(&start_upload_req.absolute_path) {
            println!(
                "StartUpload request with invalid path: {}, peer: {}",
                start_upload_req.absolute_path,
                self.peer.lock().await
            );
            let resp: file_deploy::StartUploadResponse = file_deploy::StartUploadResponse {
                success: false,
                error: "Path not allowed".to_string(),
            };
            let packet = package_data(Command::CmdStartUpload, resp);
            self.post_send(packet).await;
            return;
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&start_upload_req.absolute_path)
            .await;
        if file.is_err() {
            println!(
                "Failed to open file for upload: {}, peer: {}",
                start_upload_req.absolute_path,
                self.peer.lock().await
            );
            let resp = file_deploy::StartUploadResponse {
                success: false,
                error: format!("Failed to open file: {}", file.err().unwrap()),
            };
            let packet = package_data(Command::CmdStartUpload, resp);
            self.post_send(packet).await;
            return;
        }
        {
            if start_upload_req.total_size == 0 {
                println!(
                    "Warning: Start upload request with total_size=0 for file: {}, peer: {}",
                    start_upload_req.absolute_path,
                    self.peer.lock().await
                );
            } else {
                self.file_handles
                    .lock()
                    .await
                    .insert(start_upload_req.absolute_path.clone(), file.unwrap());
            }
        }
        let resp = file_deploy::StartUploadResponse {
            success: true,
            error: "".to_string(),
        };
        let packet = package_data(Command::CmdStartUpload, resp);
        self.post_send(packet).await;
    }

    async fn on_upload_chunk(self: Arc<Self>, payload: &[u8]) {
        if !self.clone().is_authenticated().await {
            println!(
                "Upload chunk request but not authenticated, peer: {}",
                self.peer.lock().await
            );
            let resp = file_deploy::UploadChunkResponse {
                success: false,
                offset: 0,
                error: "Not authenticated".to_string(),
            };
            let packet = package_data(Command::CmdUploadChunk, resp);
            self.post_send(packet).await;
            return;
        }
        let upload_chunk_req = file_deploy::UploadChunkRequest::decode(payload);
        if !upload_chunk_req.is_ok() {
            println!(
                "Invalid UploadChunk request, peer: {}",
                self.peer.lock().await
            );
            let resp = file_deploy::UploadChunkResponse {
                success: false,
                offset: 0,
                error: "Invalid request".to_string(),
            };
            let packet = package_data(Command::CmdUploadChunk, resp);
            self.post_send(packet).await;
            return;
        }
        let upload_chunk_req = upload_chunk_req.unwrap();
        let write_result = {
            let mut file_handles = self.file_handles.lock().await;
            if !file_handles.contains_key(&upload_chunk_req.absolute_path) {
                println!(
                    "Upload chunk for unopened file: {}, peer: {}",
                    upload_chunk_req.absolute_path,
                    self.peer.lock().await
                );
                let resp = file_deploy::UploadChunkResponse {
                    success: false,
                    offset: upload_chunk_req.offset,
                    error: "File not opened for upload".to_string(),
                };
                let packet = package_data(Command::CmdUploadChunk, resp);
                self.post_send(packet).await;
                return;
            }
            let file = file_handles
                .get_mut(&upload_chunk_req.absolute_path)
                .unwrap();
            file.write_all(&upload_chunk_req.data).await
        };
        if write_result.is_err() {
            println!(
                "Failed to write data to file: {}, peer: {}",
                upload_chunk_req.absolute_path,
                self.peer.lock().await
            );
            let resp = file_deploy::UploadChunkResponse {
                success: false,
                offset: upload_chunk_req.offset,
                error: format!("Failed to write data: {}", write_result.err().unwrap()),
            };
            let packet = package_data(Command::CmdUploadChunk, resp);
            self.post_send(packet).await;
            return;
        }
        if upload_chunk_req.is_last_chunk {
            println!(
                "Upload completed for file: {}, peer: {}",
                upload_chunk_req.absolute_path,
                self.peer.lock().await
            );
            
            let mut file_handles = self.file_handles.lock().await;
            file_handles.get(&upload_chunk_req.absolute_path).unwrap().sync_all().await.ok();
            file_handles.remove(&upload_chunk_req.absolute_path);
        }
        let resp = file_deploy::UploadChunkResponse {
            success: true,
            offset: upload_chunk_req.offset + upload_chunk_req.data.len() as u64,
            error: "".to_string(),
        };
        let packet = package_data(Command::CmdUploadChunk, resp);
        self.post_send(packet).await;
    }

    async fn on_all_done(self: Arc<Self>) {
        if !self.clone().is_authenticated().await {
            println!(
                "AllDone request but not authenticated, peer: {}",
                self.peer.lock().await
            );
            return;
        }
        self.clone()
            .post_send(package_cmd_data(Command::CmdAllDone))
            .await;
        let config = get_config();
        if let Some(script) = config.script {
            println!("Executing script: {}", script);
            let output = if cfg!(target_os = "windows") {
                std::process::Command::new("cmd")
                    .args(&["/C", &script])
                    .output()
            } else {
                std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&script)
                    .output()
            };
            match output {
                Ok(output) => {
                    if output.status.success() {
                        println!("Script executed successfully");
                    } else {
                        println!(
                            "Script execution failed with status: {}, stderr: {}",
                            output.status,
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                }
                Err(e) => {
                    println!("Failed to execute script: {}", e);
                }
            }
        } else {
            println!("No script configured to run after all files are uploaded");
        }
    }

    async fn read_loop(
        self: Arc<Self>,
        mut read_half: ReadHalf<TlsStream<TcpStream>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            if self.clone().need_stop.load(Ordering::SeqCst) {
                drop(read_half);
                return Ok(());
            }
            let mut header_buf = [0u8; data_define::PACKET_HEADER_SIZE];
            read_half.read_exact(&mut header_buf).await?;
            let command: data_define::Command =
                u32::from_le_bytes(header_buf[0..4].try_into().unwrap()).try_into()?;
            let length = u32::from_le_bytes(header_buf[4..8].try_into().unwrap()) as usize;
            let checksum = u32::from_le_bytes(header_buf[8..12].try_into().unwrap());
            if length > data_define::MAX_PAYLOAD_SIZE {
                println!(
                    "Payload too large: {}, peer: {}",
                    length,
                    self.peer.lock().await
                );
                self.clone().stop().await;
                return Err("Payload too large".into());
            }
            let mut payload_buf = vec![0u8; length];
            if length != 0 {
                read_half.read_exact(&mut payload_buf).await?;
                let payload_crc32c = crc32c::crc32c(&payload_buf);
                if payload_crc32c != checksum {
                    println!("Checksum mismatch, peer: {}", self.peer.lock().await);
                    self.clone().stop().await;
                    return Err("Checksum mismatch".into());
                }
            }
            match command {
                Command::CmdAuthenticate => {
                    self.clone().on_auth(&payload_buf).await;
                }
                Command::CmdMkDir => {
                    self.clone().on_mkdir(&payload_buf).await;
                }
                Command::CmdStartUpload => {
                    self.clone().on_start_upload(&payload_buf).await;
                }
                Command::CmdUploadChunk => {
                    self.clone().on_upload_chunk(&payload_buf).await;
                }
                Command::CmdAllDone => {
                    let session = self.clone();
                    tokio::spawn(async move {
                        session.on_all_done().await;
                    });
                }
            }
        }
    }

    async fn write_loop(
        self: Arc<Self>,
        mut write_half: WriteHalf<TlsStream<TcpStream>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let data = loop {
                if self.need_stop.load(Ordering::SeqCst) {
                    drop(write_half);
                    return Ok(());
                }
                let mut queue = self.write_queue.lock().await;
                if let Some(data) = queue.pop_front() {
                    break data;
                }
                drop(queue);
                self.notify.notified().await;
            };
            write_half.write_all(data.as_slice()).await?;
            write_half.flush().await?;
            self.notify.notify_waiters();
        }
    }

    async fn post_send(&self, data: Vec<u8>) {
        loop {
            if self.need_stop.load(Ordering::SeqCst) {
                return;
            }
            let mut queue = self.write_queue.lock().await;
            if queue.len() < data_define::MAX_QUEUE_LEN.into() {
                queue.push_back(data);
                self.notify.notify_waiters();
                break;
            }
            drop(queue);
            self.notify.notified().await;
        }
    }

    pub(crate) async fn run(
        self: Arc<Self>,
        stream: TcpStream,
        acceptor: TlsAcceptor,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        *self.peer.lock().await = stream.peer_addr()?.to_string();
        let stream = acceptor.accept(stream).await?;
        let (read, write) = split(stream);
        let mut join_set = JoinSet::new();

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let session = self.clone();
        join_set.spawn(async move {
            let _ = session.read_loop(read).await;
            let _ = shutdown_tx.send(());
        });
        let session = self.clone();
        join_set.spawn(async move {
            let _ = tokio::select! {
                res = session.write_loop(write) => res,
                _ = shutdown_rx => Ok(()),
            };
            self.clone().stop().await;
        });
        join_set.join_all().await;
        println!("session exited");
        Ok(())
    }

    async fn stop(&self) {
        self.need_stop.store(true, Ordering::SeqCst);
        {
            let mut queue = self.write_queue.lock().await;
            queue.clear();
        }
        self.notify.notify_waiters();
    }
}
