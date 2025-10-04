use std::vec::Vec;
use prost::Message;
use crc32c::crc32c;

pub(crate) const PACKET_HEADER_SIZE: usize = 12; // 4 bytes command, 4 bytes length, 4 bytes checksum
pub(crate) const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MB
pub(crate) const MAX_QUEUE_LEN: u16 = 100; // 4 KB
#[derive(Debug)]
pub(crate) enum Command {
    CmdAuthenticate = 1,
    CmdMkDir,
    CmdStartUpload,
    CmdUploadChunk,
    CmdAllDone,
}

impl TryInto<Command> for u32 {
    type Error = &'static str;

    fn try_into(self) -> Result<Command, Self::Error> {
        match self {
            1 => Ok(Command::CmdAuthenticate),
            2 => Ok(Command::CmdMkDir),
            3 => Ok(Command::CmdStartUpload),
            4 => Ok(Command::CmdUploadChunk),
            5 => Ok(Command::CmdAllDone),
            _ => Err("Unknown command"),
        }
    }
}

pub(crate) fn package_data(cmd: Command, msg: impl Message) -> Vec<u8> 
{
    let msg_len = msg.encoded_len();
    let data_len = PACKET_HEADER_SIZE + msg_len;
    let mut data_package = Vec::with_capacity(data_len);

    data_package.extend_from_slice(&(cmd as u32).to_le_bytes());
    data_package.extend_from_slice(&(msg_len as u32).to_le_bytes());

    // Reserve space for checksum (4 bytes)
    data_package.extend_from_slice(&[0u8; 4]);

    // Encode protobuf directly into the buffer to avoid extra copy
    msg.encode(&mut data_package).unwrap();

    // Calculate checksum for the protobuf part
    let checksum = crc32c(&data_package[PACKET_HEADER_SIZE..]);

    // Write checksum into the reserved space
    let checksum_bytes = checksum.to_le_bytes();
    let checksum_pos = 8; 
    data_package[checksum_pos..checksum_pos + 4].copy_from_slice(&checksum_bytes);

    data_package
}

pub(crate) fn package_cmd_data(cmd: Command) -> Vec<u8> 
{
    let data_len = PACKET_HEADER_SIZE;
    let mut data_package = Vec::with_capacity(data_len);

    data_package.extend_from_slice(&(cmd as u32).to_le_bytes());
    data_package.extend_from_slice(&[0u8; 4]);
    // Reserve space for checksum (4 bytes)
    data_package.extend_from_slice(&[0u8; 4]);

    data_package
}