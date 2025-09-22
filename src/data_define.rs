pub(crate) const PACKET_HEADER_SIZE: usize = 12; // 4 bytes command, 4 bytes length, 4 bytes checksum
pub(crate) const MAX_PAYLOAD_SIZE: usize = 1 * 1024 * 1024; // 10 MB
pub(crate) enum Command {
    CmdAuthenticate = 1,
}

impl TryInto<Command> for u32 {
    type Error = &'static str;

    fn try_into(self) -> Result<Command, Self::Error> {
        match self {
            1 => Ok(Command::CmdAuthenticate),
            _ => Err("Unknown command"),
        }
    }
}