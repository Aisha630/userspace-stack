use crate::MacAddr;

pub const PACKET_LEN: usize = 28;
pub const REQUEST: u16 = 1;
pub const REPLY: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub operation: u16,
    pub sender_mac: MacAddr,
    pub sender_ip: [u8; 4],
    pub target_mac: MacAddr,
    pub target_ip: [u8; 4],
}

impl Packet {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < PACKET_LEN
            || u16::from_be_bytes(bytes[0..2].try_into().ok()?) != 1
            || u16::from_be_bytes(bytes[2..4].try_into().ok()?) != 0x0800
            || bytes[4] != 6
            || bytes[5] != 4
        {
            return None;
        }
        Some(Self {
            operation: u16::from_be_bytes(bytes[6..8].try_into().ok()?),
            sender_mac: bytes[8..14].try_into().ok()?,
            sender_ip: bytes[14..18].try_into().ok()?,
            target_mac: bytes[18..24].try_into().ok()?,
            target_ip: bytes[24..28].try_into().ok()?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PACKET_LEN);
        bytes.extend_from_slice(&1u16.to_be_bytes());
        bytes.extend_from_slice(&0x0800u16.to_be_bytes());
        bytes.extend_from_slice(&[6, 4]);
        bytes.extend_from_slice(&self.operation.to_be_bytes());
        bytes.extend_from_slice(&self.sender_mac);
        bytes.extend_from_slice(&self.sender_ip);
        bytes.extend_from_slice(&self.target_mac);
        bytes.extend_from_slice(&self.target_ip);
        bytes
    }
}
