use crate::checksum;

pub const HEADER_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

impl<'a> Datagram<'a> {
    pub fn parse(src: [u8; 4], dst: [u8; 4], bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN {
            return None;
        }
        let len = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        if len < HEADER_LEN || len > bytes.len() {
            return None;
        }
        let received = u16::from_be_bytes([bytes[6], bytes[7]]);
        if received != 0 && checksum::pseudo_header(src, dst, 17, &bytes[..len]) != 0 {
            return None;
        }
        Some(Self {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            payload: &bytes[HEADER_LEN..len],
        })
    }
}

pub fn serialize(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    assert!(payload.len() <= u16::MAX as usize - HEADER_LEN);
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
    bytes.resize(HEADER_LEN, 0);
    bytes[0..2].copy_from_slice(&src_port.to_be_bytes());
    bytes[2..4].copy_from_slice(&dst_port.to_be_bytes());
    bytes[4..6].copy_from_slice(&((HEADER_LEN + payload.len()) as u16).to_be_bytes());
    bytes.extend_from_slice(payload);
    let mut sum = checksum::pseudo_header(src_ip, dst_ip, 17, &bytes);
    if sum == 0 {
        sum = 0xffff;
    }
    bytes[6..8].copy_from_slice(&sum.to_be_bytes());
    bytes
}
