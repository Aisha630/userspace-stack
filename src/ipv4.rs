use crate::checksum;

pub const PROTOCOL_ICMP: u8 = 1;
pub const PROTOCOL_TCP: u8 = 6;
pub const PROTOCOL_UDP: u8 = 17;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    pub dscp_ecn: u8,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Truncated,
    Version,
    HeaderLength,
    TotalLength,
    Checksum,
    Fragmented,
}

impl<'a> Packet<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() < 20 {
            return Err(ParseError::Truncated);
        }
        if bytes[0] >> 4 != 4 {
            return Err(ParseError::Version);
        }
        let header_len = ((bytes[0] & 0x0f) as usize) * 4;
        if header_len < 20 || bytes.len() < header_len {
            return Err(ParseError::HeaderLength);
        }
        let total_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if total_len < header_len || total_len > bytes.len() {
            return Err(ParseError::TotalLength);
        }
        if checksum::internet(&bytes[..header_len]) != 0 {
            return Err(ParseError::Checksum);
        }
        let flags_fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
        if flags_fragment & 0x3fff != 0 {
            return Err(ParseError::Fragmented);
        }
        Ok(Self {
            dscp_ecn: bytes[1],
            identification: u16::from_be_bytes([bytes[4], bytes[5]]),
            flags_fragment,
            ttl: bytes[8],
            protocol: bytes[9],
            src: bytes[12..16]
                .try_into()
                .map_err(|_| ParseError::Truncated)?,
            dst: bytes[16..20]
                .try_into()
                .map_err(|_| ParseError::Truncated)?,
            payload: &bytes[header_len..total_len],
        })
    }
}

pub fn serialize(
    src: [u8; 4],
    dst: [u8; 4],
    protocol: u8,
    identification: u16,
    payload: &[u8],
) -> Vec<u8> {
    assert!(payload.len() <= u16::MAX as usize - 20);
    let mut bytes = vec![0u8; 20];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    bytes[4..6].copy_from_slice(&identification.to_be_bytes());
    bytes[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = protocol;
    bytes[12..16].copy_from_slice(&src);
    bytes[16..20].copy_from_slice(&dst);
    let sum = checksum::internet(&bytes);
    bytes[10..12].copy_from_slice(&sum.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
