use crate::data_define::*;
use prost::Message;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::TcpStream;
use tokio::sync::{Mutex as AsyncMutex, Notify, oneshot};
use tokio::task::JoinSet;
use tokio_rustls::{TlsAcceptor, server::TlsStream};
mod file_deploy {
    include!(concat!(env!("OUT_DIR"), "/file_deploy.rs"));
}

use crate::data_define;
use crate::server::config::get_config;

const MAX_QUEUE_LEN: usize = 128;

pub(crate) struct Session {
    authenticated: AsyncMutex<bool>,
    write_queue: AsyncMutex<VecDeque<Vec<u8>>>,
    notify: Notify,
    file_handles: AsyncMutex<std::collections::HashMap<String, tokio::fs::File>>,
}

fn is_valid_path(path: &str) -> bool {
    let config = get_config();
    for white_dir in config.whitelisted_dirs {
        let white_dir = white_dir.to_str().unwrap().to_string();
        if path.starts_with(white_dir.trim_end_matches(std::path::MAIN_SEPARATOR)) {
            return true;
        }
    }
    false
}

impl Session {
    pub(crate) fn new() -> Self {
        Session {
            authenticated: AsyncMutex::new(false),
            write_queue: AsyncMutex::new(VecDeque::new()),
            notify: Notify::new(),
            file_handles: AsyncMutex::new(std::collections::HashMap::new()),
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
                *self.authenticated.lock().await = true;
            }
        }
        // 发送认证结果
        let auth_resp = file_deploy::AuthResponse {
            success: *self.authenticated.lock().await,
        };
        let packet = package_data(Command::CmdAuthenticate, auth_resp);
        self.post_send(packet).await;
    }

    async fn on_mkdir(self: Arc<Self>, payload: &[u8]) {
        if !self.clone().is_authenticated().await {
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
            let resp = file_deploy::MkDirResponse {
                success: false,
                error: "Invalid request".to_string(),
            };
            let packet = package_data(Command::CmdMkDir, resp);
            self.post_send(packet).await;
            return;
        }
        let mk_dir_req = mk_dir_req.unwrap();
        if !is_valid_path(&mk_dir_req.absolute_path) {
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
            let resp = file_deploy::StartUploadResponse {
                success: false,
                error: "Invalid request".to_string(),
            };
            let packet = package_data(Command::CmdStartUpload, resp);
            self.post_send(packet).await;
            return;
        }
        let start_upload_req = start_upload_req.unwrap();

        if !is_valid_path(&start_upload_req.absolute_path) {
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
            let resp = file_deploy::StartUploadResponse {
                success: false,
                error: format!("Failed to open file: {}", file.err().unwrap()),
            };
            let packet = package_data(Command::CmdStartUpload, resp);
            self.post_send(packet).await;
            return;
        }
        {
            self.file_handles
                .lock()
                .await
                .insert(start_upload_req.absolute_path.clone(), file.unwrap());
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
            let mut file_handles = self.file_handles.lock().await;
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

    async fn read_loop(
        self: Arc<Self>,
        mut read_half: ReadHalf<TlsStream<TcpStream>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let mut header_buf = [0u8; data_define::PACKET_HEADER_SIZE];
            read_half.read_exact(&mut header_buf).await?;
            let command: data_define::Command =
                u32::from_le_bytes(header_buf[0..4].try_into().unwrap()).try_into()?;
            let length = u32::from_le_bytes(header_buf[4..8].try_into().unwrap()) as usize;
            let checksum = u32::from_le_bytes(header_buf[8..12].try_into().unwrap());
            if length > data_define::MAX_PAYLOAD_SIZE {
                return Err("Payload too large".into());
            }
            let mut payload_buf = vec![0u8; length];
            read_half.read_exact(&mut payload_buf).await?;
            let payload_crc32c = crc32c::crc32c(&payload_buf);
            if payload_crc32c != checksum {
                return Err("Checksum mismatch".into());
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
            }
        }
    }

    async fn write_loop(
        self: Arc<Self>,
        mut write_half: WriteHalf<TlsStream<TcpStream>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            // 等待队列有数据
            let data = loop {
                let mut queue = self.write_queue.lock().await;
                if let Some(data) = queue.pop_front() {
                    // 队列有数据，取出一个包
                    break data;
                }
                drop(queue);
                self.notify.notified().await;
            };
            // 发送数据
            write_half.write_all(data.as_slice()).await?;
            self.notify.notify_one();
        }
    }

    async fn post_send(&self, data: Vec<u8>) {
        loop {
            let mut queue = self.write_queue.lock().await;
            if queue.len() < MAX_QUEUE_LEN {
                queue.push_back(data);
                self.notify.notify_one();
                break;
            }
            // 队列满了，释放锁，等待有空间
            drop(queue);
            self.notify.notified().await;
        }
    }

    pub(crate) async fn run(
        self: Arc<Self>,
        stream: TcpStream,
        acceptor: TlsAcceptor,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let stream = acceptor.accept(stream).await?;
        let (read, write) = split(stream);
        let mut join_set = JoinSet::new();

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let session = self.clone();
        join_set.spawn(async move {
            let _ = session.read_loop(read).await;
            let _ = shutdown_tx.send(());
        });
        join_set.spawn(async move {
            let _ = tokio::select! {
                res = self.write_loop(write) => res,
                _ = &mut shutdown_rx => Ok(()),
            };
        });
        join_set.join_all().await;
        Ok(())
    }
}
