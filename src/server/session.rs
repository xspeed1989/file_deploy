use prost::Message;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex as StdMutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio_rustls::{TlsAcceptor, server::TlsStream};

mod file_deploy {
    include!(concat!(env!("OUT_DIR"), "/file_deploy.rs"));
}

use crate::data_define;
use crate::server::config::get_config;
const MAX_QUEUE_LEN: usize = 128;
pub(crate) struct Session {
    authenticated: StdMutex<bool>,
    write_queue: StdMutex<VecDeque<Vec<u8>>>,
    cond_var: Condvar,
}

impl Session {
    pub(crate) fn new() -> Self {
        Session {
            authenticated: StdMutex::new(false),
            write_queue: StdMutex::new(VecDeque::new()),
            cond_var: Condvar::new(),
        }
    }

    async fn on_auth(self: Arc<Self>, payload: &[u8]) {
        let auth_req = file_deploy::AuthRequest::decode(payload);
        if auth_req.is_ok() {
            let auth_req = auth_req.unwrap();
            let config = get_config();
            if auth_req.password == config.password {
                *self.authenticated.lock().unwrap() = true;
            }
        }
        // 发送认证结果
        let auth_resp = file_deploy::AuthResponse {
            success: *self.authenticated.lock().unwrap(),
        };
        let mut resp_buf = Vec::new();
        auth_resp.encode(&mut resp_buf).unwrap();
        let mut packet = Vec::with_capacity(data_define::PACKET_HEADER_SIZE + resp_buf.len());

        packet.extend_from_slice(&(data_define::Command::CmdAuthenticate as u32).to_le_bytes());
        packet.extend_from_slice(&(resp_buf.len() as u32).to_le_bytes());
        let checksum = crc32c::crc32c(&resp_buf);
        packet.extend_from_slice(&checksum.to_le_bytes());
        packet.extend_from_slice(&resp_buf);
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
                data_define::Command::CmdAuthenticate => {
                    self.clone().on_auth(&payload_buf).await;
                }
            }
        }
    }

    async fn write_loop(
        self: Arc<Self>,
        mut write_half: WriteHalf<TlsStream<TcpStream>>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            let mut local_queue = {
                let mut queue = self.write_queue.lock().unwrap();
                while queue.is_empty() {
                    queue = self.cond_var.wait(queue).unwrap();
                }
                let mut q = VecDeque::new();
                std::mem::swap(&mut *queue, &mut q);
                q
            };
            if let Some(data) = local_queue.pop_front() {
                write_half.write_all(data.as_slice()).await?;
                self.cond_var.notify_one();
            }
        }
    }

    async fn post_send(&self, data: Vec<u8>) {
        let mut queue = self.write_queue.lock().unwrap();
        while queue.len() >= MAX_QUEUE_LEN {
            // 队列满了，等待空间
            queue = self.cond_var.wait(queue).unwrap();
        }
        queue.push_back(data);
        self.cond_var.notify_one();
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
