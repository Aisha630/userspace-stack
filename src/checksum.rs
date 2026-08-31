/// Computes the Internet checksum from RFC 1071.
pub fn internet(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn pseudo_header(src: [u8; 4], dst: [u8; 4], protocol: u8, segment: &[u8]) -> u16 {
    let mut bytes = Vec::with_capacity(12 + segment.len());
    bytes.extend_from_slice(&src);
    bytes.extend_from_slice(&dst);
    bytes.push(0);
    bytes.push(protocol);
    bytes.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    bytes.extend_from_slice(segment);
    internet(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ipv4_header_checksum() {
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(internet(&header), 0);
    }

    #[test]
    fn odd_length_checksum() {
        assert_eq!(internet(&[0x01, 0x02, 0x03]), 0xfbfd);
    }
}
