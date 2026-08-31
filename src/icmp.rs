use crate::checksum;

pub const ECHO_REPLY: u8 = 0;
pub const ECHO_REQUEST: u8 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    pub kind: u8,
    pub code: u8,
    pub rest: [u8; 4],
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 8 || checksum::internet(bytes) != 0 {
            return None;
        }
        Some(Self {
            kind: bytes[0],
            code: bytes[1],
            rest: bytes[4..8].try_into().ok()?,
            payload: &bytes[8..],
        })
    }

    pub fn echo_reply(&self) -> Option<Vec<u8>> {
        (self.kind == ECHO_REQUEST && self.code == 0)
            .then(|| serialize(ECHO_REPLY, 0, self.rest, self.payload))
    }
}

pub fn serialize(kind: u8, code: u8, rest: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(8 + payload.len());
    bytes.extend_from_slice(&[kind, code, 0, 0]);
    bytes.extend_from_slice(&rest);
    bytes.extend_from_slice(payload);
    let sum = checksum::internet(&bytes);
    bytes[2..4].copy_from_slice(&sum.to_be_bytes());
    bytes
}
