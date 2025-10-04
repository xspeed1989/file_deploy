use crate::data_define;
use crate::file_deploy;
use async_recursion::async_recursion;
use prost::Message;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::vec::Vec;
use tokio::io::split;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tokio::task::JoinSet;
use tokio_rustls::client::TlsStream;

const FILE_CHUNK_SIZE: usize = 1 * 1024 * 1024; // 1MB

pub(crate) struct Connection {
    pub password: String,
    pub tasks: Vec<super::DeployPathPair>,
    sender_notify: Notify,
    send_queue: AsyncMutex<VecDeque<Vec<u8>>>,
    need_stop: AtomicBool,
}

impl Connection {
    pub(crate) fn new(password: String, tasks: Vec<super::DeployPathPair>) -> Self {
        Self {
            password,
            tasks,
            sender_notify: Notify::new(),
            send_queue: AsyncMutex::new(VecDeque::new()),
            need_stop: AtomicBool::new(false),
        }
    }

    async fn do_stop(&self) {
        self.need_stop.store(true, Ordering::SeqCst);
        {
            let mut queue = self.send_queue.lock().await;
            queue.clear();
        }
        self.sender_notify.notify_waiters();
    }

    async fn read_loop(
        self: Arc<Self>,
        mut read_half: ReadHalf<TlsStream<TcpStream>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            if self.need_stop.load(Ordering::SeqCst) {
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
                self.do_stop().await;
                return Err("Payload too large".into());
            }

            let mut payload_buf = vec![0u8; length];
            if length > 0 {
                read_half.read_exact(&mut payload_buf).await?;
                let payload_crc32c = crc32c::crc32c(&payload_buf);
                if payload_crc32c != checksum {
                    self.do_stop().await;
                    return Err("Checksum mismatch".into());
                }
            }
            match command {
                data_define::Command::CmdAuthenticate => {
                    self.on_auth_response(&payload_buf).await;
                }
                data_define::Command::CmdMkDir => {
                    self.on_mkdir_response(&payload_buf).await;
                }
                data_define::Command::CmdStartUpload => {
                    self.on_start_upload_response(&payload_buf).await;
                }
                data_define::Command::CmdUploadChunk => {
                    self.on_upload_chunk_response(&payload_buf).await;
                }
                data_define::Command::CmdAllDone => {
                    println!("All tasks completed");
                    self.do_stop().await;
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
                let mut queue = self.send_queue.lock().await;
                if let Some(data) = queue.pop_front() {
                    break data;
                }
                drop(queue);
                self.sender_notify.notified().await;
            };
            let res = write_half.write_all(&data).await;
            if res.is_err() {
                self.do_stop().await;
                return Err("Failed to write to stream".into());
            }
            self.sender_notify.notify_one();
        }
    }

    async fn post_send(&self, data: Vec<u8>) {
        loop {
            if self.need_stop.load(Ordering::SeqCst) {
                return;
            }
            {
                let mut queue = self.send_queue.lock().await;
                if queue.len() < data_define::MAX_QUEUE_LEN.into() {
                    queue.push_back(data);
                    self.sender_notify.notify_one();
                    break;
                }
                drop(queue);
            }
            self.sender_notify.notified().await;
        }
    }

    async fn do_auth(self: Arc<Self>) {
        let req = file_deploy::AuthRequest {
            password: self.password.clone(),
        };
        self.post_send(data_define::package_data(
            data_define::Command::CmdAuthenticate,
            req,
        ))
        .await;
    }

    async fn on_auth_response(self: &Arc<Self>, payload: &[u8]) {
        let auth_res = file_deploy::AuthResponse::decode(payload);
        if auth_res.is_err() {
            println!("Failed to decode authentication response");
            self.do_stop().await;
            return;
        }
        let auth_res = auth_res.unwrap();
        if !auth_res.success {
            println!("Authentication failed: password incorrect");
            self.do_stop().await;
        }
        println!("Authentication successful");
        tokio::spawn(self.clone().do_tasks());
    }

    async fn on_mkdir_response(&self, payload: &[u8]) {
        let res = file_deploy::MkDirResponse::decode(payload);
        if res.is_err() {
            println!("Failed to decode mkdir response");
            self.do_stop().await;
            return;
        }
        let res = res.unwrap();
        if !res.success {
            println!("Failed to create remote directory: {}", res.error);
            self.do_stop().await;
        }
    }

    async fn on_start_upload_response(&self, payload: &[u8]) {
        let res = file_deploy::StartUploadResponse::decode(payload);
        if res.is_err() {
            println!("Failed to decode start upload response");
            self.do_stop().await;
            return;
        }
        let res = res.unwrap();
        if !res.success {
            println!("Failed to start upload: {}", res.error);
            self.do_stop().await;
        }
    }

    async fn on_upload_chunk_response(&self, payload: &[u8]) {
        let res = file_deploy::UploadChunkResponse::decode(payload);
        if res.is_err() {
            println!("Failed to decode upload chunk response");
            self.do_stop().await;
            return;
        }
        let res = res.unwrap();
        if !res.success {
            println!("Failed to upload chunk: {}", res.error);
            self.do_stop().await;
        }
    }

    async fn create_remote_dir(
        &self,
        remote: &String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let req = file_deploy::MkDirRequest {
            absolute_path: remote.clone(),
        };
        self.post_send(data_define::package_data(
            data_define::Command::CmdMkDir,
            req,
        ))
        .await;
        Ok(())
    }

    #[async_recursion]
    async fn upload_directory(
        self: Arc<Self>,
        local: PathBuf,
        remote: &String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!(
            "Creating remote directory {} for local directory {}",
            remote,
            local.clone().display()
        );
        self.clone().create_remote_dir(remote).await?;
        let mut dir_entries = tokio::fs::read_dir(&local).await?;
        while let Some(entry) = dir_entries.next_entry().await? {
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();
            let remote_path = if remote.ends_with('/') {
                format!("{}{}", remote, file_name)
            } else {
                format!("{}/{}", remote, file_name)
            };
            if path.is_dir() {
                self.clone()
                    .upload_directory(path.clone(), &remote_path)
                    .await?;
            } else if path.is_file() {
                self.clone().upload_file(path.clone(), &remote_path).await?;
            }
        }
        Ok(())
    }

    async fn upload_file(
        self: Arc<Self>,
        local: PathBuf,
        remote: &String,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("Uploading file {} to {}", local.clone().display(), remote);
        let metadata = tokio::fs::metadata(&local).await?;
        let mut file_size = metadata.len();
        let req = file_deploy::StartUploadRequest {
            absolute_path: remote.clone(),
            total_size: file_size,
        };
        self.clone()
            .post_send(data_define::package_data(
                data_define::Command::CmdStartUpload,
                req,
            ))
            .await;

        let mut file = tokio::fs::File::open(&local).await?;
        while file_size > 0 {
            let mut buffer = vec![0u8; FILE_CHUNK_SIZE];
            let n = file.read(&mut buffer).await?;
            if n == 0 {
                break; // EOF
            }
            buffer.truncate(n);
            let chunk_req = file_deploy::UploadChunkRequest {
                absolute_path: remote.clone(),
                offset: metadata.len() - file_size,
                data: buffer,
                is_last_chunk: file_size - n as u64 == 0,
            };
            self.clone()
                .post_send(data_define::package_data(
                    data_define::Command::CmdUploadChunk,
                    chunk_req,
                ))
                .await;
            file_size -= n as u64;
        }
        Ok(())
    }

    async fn do_tasks(self: Arc<Self>) {
        for task in &self.tasks {
            let local_path = PathBuf::from(&task.0);
            let remote_path = task.1.clone();
            if (&local_path).is_dir() {
                if let Err(e) = self
                    .clone()
                    .upload_directory(local_path.clone(), &remote_path)
                    .await
                {
                    println!(
                        "Failed to upload directory {}: {}",
                        local_path.clone().display(),
                        e
                    );
                    self.do_stop().await;
                    return;
                }
            } else if (&local_path).is_file() {
                let file_name = local_path
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                let remote_path = if remote_path.ends_with('/') {
                    format!("{}{}", remote_path, file_name)
                } else {
                    format!("{}/{}", remote_path, file_name)
                };
    
                if let Err(e) = self
                    .clone()
                    .upload_file(local_path.clone(), &remote_path)
                    .await
                {
                    println!(
                        "Failed to upload file {}: {}",
                        local_path.clone().display(),
                        e
                    );
                    self.do_stop().await;
                    return;
                }
            } else {
                println!(
                    "Path {} is neither a file nor a directory",
                    local_path.display()
                );
            }
        }
        self.post_send(data_define::package_cmd_data(
            data_define::Command::CmdAllDone,
        ))
        .await;
    }

    pub(crate) async fn run(
        self: Arc<Self>,
        stream: TlsStream<TcpStream>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (read_half, write_half) = split(stream);
        let mut join_set = JoinSet::new();

        let (tx, rx) = oneshot::channel::<()>();
        let conn = self.clone();
        join_set.spawn(async move {
            let result = conn.read_loop(read_half).await;
            let _ = tx.send(());
            result
        });

        let conn = self.clone();
        join_set.spawn(async move {
            let res = tokio::select! {
                res = conn.clone().write_loop(write_half) => res,
                _ = rx => Ok(()),
            };
            conn.do_stop().await;
            res
        });

        let conn = self.clone();
        join_set.spawn(async move {
            conn.do_auth().await;
            Ok(())
        });

        join_set.join_all().await;
        println!("Connection finished");
        Ok(())
    }
}
